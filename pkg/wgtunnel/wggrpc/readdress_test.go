// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package wggrpc_test

import (
	"context"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/metadata"

	pb "github.com/siderolabs/siderolink/api/siderolink"
	"github.com/siderolabs/siderolink/pkg/wgtunnel/wgbind"
	"github.com/siderolabs/siderolink/pkg/wgtunnel/wggrpc"
)

// TestReaddressedPeerKeepsCurrentEndpoint covers a peer that re-provisions onto a new tunnel address
// while a packet from its previous connection is still queued. The packet must come out tagged with
// the peer's current address: WireGuard adopts the address of every packet it accepts as the peer's
// endpoint, so surfacing the old one would point the send path at a connection that no longer exists.
func TestReaddressedPeerKeepsCurrentEndpoint(t *testing.T) {
	const (
		oldAddr = "[fdae:41e4:649b:9304::1]:50888"
		newAddr = "[fdae:41e4:649b:9304::2]:50888"
	)

	oldAddrPort := netip.MustParseAddrPort(oldAddr)
	newAddrPort := netip.MustParseAddrPort(newAddr)

	pubKey := wgtypes.Key{1}

	pt := wgbind.NewPeerTraffic(1, zap.NewNop())
	ap := wggrpc.NewAllowedPeers()
	ap.AddToken(pubKey, oldAddrPort.Addr().String())

	svc := wggrpc.NewService(pt, ap, zap.NewNop())

	// Stream A is the peer's connection on its old address. It delivers a single packet and then parks,
	// so the packet is queued but not yet consumed when the peer moves.
	ctxA, cancelA := context.WithCancel(metadata.NewIncomingContext(t.Context(),
		metadata.Pairs(wggrpc.PeerAddrKey, oldAddr)))
	defer cancelA()

	aPushed := make(chan struct{})
	aRecvCalls := 0
	aDone := make(chan error, 1)

	streamA := &fakeStream{
		ctx: ctxA,
		recv: func() (*pb.PeerPacket, error) {
			aRecvCalls++
			if aRecvCalls == 1 {
				return &pb.PeerPacket{Data: []byte("queued before the peer moved")}, nil
			}

			// The second call can only happen once the first packet has been pushed to the queue.
			close(aPushed)

			<-ctxA.Done()

			return nil, io.EOF
		},
		send: func(*pb.PeerPacket) error {
			<-ctxA.Done()

			return io.EOF
		},
	}

	go func() { aDone <- svc.CreateStream(streamA) }()

	select {
	case <-aPushed:
	case <-time.After(time.Second * 2):
		t.Fatal("stream A never pushed its packet")
	}

	oldQueue, ok := pt.GetSendQueue(oldAddrPort)
	require.True(t, ok, "stream A never installed its queue")

	// The peer re-provisions: it is handed a new tunnel address, and reconnects on it.
	ap.AddToken(pubKey, newAddrPort.Addr().String())

	ctxB, cancelB := context.WithCancel(metadata.NewIncomingContext(t.Context(),
		metadata.Pairs(wggrpc.PeerAddrKey, newAddr)))
	defer cancelB()

	bStarted := make(chan struct{}, 1)
	bDone := make(chan error, 1)

	streamB := &fakeStream{
		ctx: ctxB,
		recv: func() (*pb.PeerPacket, error) {
			select {
			case bStarted <- struct{}{}:
			default:
			}

			<-ctxB.Done()

			return nil, io.EOF
		},
		send: func(*pb.PeerPacket) error {
			<-ctxB.Done()

			return io.EOF
		},
	}

	go func() { bDone <- svc.CreateStream(streamB) }()

	select {
	case <-bStarted:
	case <-time.After(time.Second * 2):
		t.Fatal("stream B never started")
	}

	// Even though it arrived on a different address, B is the same peer, so it displaces A.
	select {
	case err := <-aDone:
		assert.ErrorIs(t, err, wggrpc.ErrPeerReplaced)
	case <-time.After(time.Second * 2):
		t.Fatal("stream A was not replaced")
	}

	newQueue, ok := pt.GetSendQueue(newAddrPort)
	require.True(t, ok, "the peer's new address must resolve to its send queue")
	assert.Same(t, oldQueue, newQueue, "the peer must keep the packets staged for it across the move")

	_, ok = pt.GetSendQueue(oldAddrPort)
	assert.False(t, ok, "the peer's old address must stop resolving")

	// The packet queued by A comes out tagged with the address the peer is reachable at now.
	popCtx, popCancel := context.WithTimeout(t.Context(), time.Second*2)
	defer popCancel()

	data, err := pt.PopRecvData(popCtx)
	require.NoError(t, err)
	assert.Equal(t, "queued before the peer moved", string(data.Packet.Data))
	assert.Equal(t, newAddrPort, data.Addr)

	// The address the peer left behind is no longer a valid credential either, so a stale connection
	// cannot come back and take the peer over again.
	ctxC, cancelC := context.WithCancel(metadata.NewIncomingContext(t.Context(),
		metadata.Pairs(wggrpc.PeerAddrKey, oldAddr)))
	defer cancelC()

	streamC := &fakeStream{
		ctx:  ctxC,
		recv: func() (*pb.PeerPacket, error) { return nil, io.EOF },
		send: func(*pb.PeerPacket) error { return io.EOF },
	}

	assert.ErrorIs(t, svc.CreateStream(streamC), wggrpc.ErrPeerNotAllowed)

	// A stream's receive goroutine outlives CreateStream and only unblocks when its transport closes,
	// so both transports have to go before the service can be drained.
	cancelA()
	cancelB()

	select {
	case <-bDone:
	case <-time.After(time.Second * 2):
		t.Fatal("stream B never returned")
	}

	// Drain the service's goroutines before returning, so none of them outlive the test.
	svc.Wait()
}

// TestReassignedAddressDisplacesPreviousPeer covers a tunnel address that is handed over to a different
// peer while the peer that held it before is still connected. The old peer's stream must be retired
// along with its session: otherwise it keeps running detached from any session, still consuming from the
// shared receive queue and never told it lost the address.
func TestReassignedAddressDisplacesPreviousPeer(t *testing.T) {
	const addr = "[fdae:41e4:649b:9304::3]:50888"

	addrPort := netip.MustParseAddrPort(addr)
	token := addrPort.Addr().String()

	keyA := wgtypes.Key{1}
	keyB := wgtypes.Key{2}

	pt := wgbind.NewPeerTraffic(1, zap.NewNop())
	ap := wggrpc.NewAllowedPeers()
	ap.AddToken(keyA, token)

	svc := wggrpc.NewService(pt, ap, zap.NewNop())

	md := metadata.Pairs(wggrpc.PeerAddrKey, addr)

	// startStream connects the peer on the shared address, and returns a way to close its transport, a
	// signal that its stream is up, and the stream's result.
	startStream := func() (context.CancelFunc, <-chan struct{}, <-chan error) {
		ctx, cancel := context.WithCancel(metadata.NewIncomingContext(t.Context(), md))

		started := make(chan struct{}, 1)
		done := make(chan error, 1)

		stream := &fakeStream{
			ctx: ctx,
			recv: func() (*pb.PeerPacket, error) {
				select {
				case started <- struct{}{}:
				default:
				}

				<-ctx.Done()

				return nil, io.EOF
			},
			send: func(*pb.PeerPacket) error {
				<-ctx.Done()

				return io.EOF
			},
		}

		go func() { done <- svc.CreateStream(stream) }()

		return cancel, started, done
	}

	waitFor := func(ch <-chan struct{}, what string) {
		select {
		case <-ch:
		case <-time.After(time.Second * 2):
			t.Fatal(what)
		}
	}

	cancelA, aStarted, aDone := startStream()
	defer cancelA()

	waitFor(aStarted, "stream A never started")

	// The address is re-assigned to another peer, which then connects on it.
	ap.AddToken(keyB, token)

	cancelB, bStarted, bDone := startStream()
	defer cancelB()

	waitFor(bStarted, "stream B never started")

	select {
	case err := <-aDone:
		assert.ErrorIs(t, err, wggrpc.ErrPeerReplaced)
	case <-time.After(time.Second * 2):
		t.Fatal("stream A was not displaced")
	}

	_, ok := pt.GetSendQueue(addrPort)
	assert.True(t, ok, "the address must resolve to the new holder's send queue")

	// A cannot come back as itself: the credential now belongs to B.
	holder, ok := ap.PubKeyForToken(token)
	require.True(t, ok)
	assert.Equal(t, keyB, holder, "the token must belong to the new holder")

	cancelA()
	cancelB()

	select {
	case <-bDone:
	case <-time.After(time.Second * 2):
		t.Fatal("stream B never returned")
	}

	svc.Wait()
}
