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

// fakeStream is a minimal WireGuardOverGRPCService_CreateStreamServer whose context, Recv and Send are
// controllable, so a test can force a specific ordering of two streams for the same peer.
type fakeStream struct {
	ctx  context.Context //nolint:containedctx
	recv func() (*pb.PeerPacket, error)
	send func(*pb.PeerPacket) error
}

func (f *fakeStream) Context() context.Context      { return f.ctx }
func (f *fakeStream) Recv() (*pb.PeerPacket, error) { return f.recv() }
func (f *fakeStream) Send(p *pb.PeerPacket) error   { return f.send(p) }
func (f *fakeStream) SetHeader(metadata.MD) error   { return nil }
func (f *fakeStream) SendHeader(metadata.MD) error  { return nil }
func (f *fakeStream) SetTrailer(metadata.MD)        {}
func (f *fakeStream) SendMsg(any) error             { return nil }
func (f *fakeStream) RecvMsg(any) error             { return nil }

// TestCleanupDoesNotDropReplacementQueue reproduces the ownership hazard: an old stream whose transport
// context is already canceled must not delete the send queue of the replacement stream that took over
// its peer address. It forces the exact ordering (old transport canceled, replacement installed, then
// the old stream cleans up) and asserts the peer's send queue survives.
func TestCleanupDoesNotDropReplacementQueue(t *testing.T) {
	peerAddr := "[fdae:41e4:649b:9304::1]:50889"
	token := netip.MustParseAddrPort(peerAddr).Addr().String()

	pt := wgbind.NewPeerTraffic(1)
	ap := wggrpc.NewAllowedPeers()
	ap.AddToken(wgtypes.Key{1}, token)

	svc := wggrpc.NewService(pt, ap, zap.NewNop())

	md := metadata.Pairs(wggrpc.PeerAddrKey, peerAddr)

	// Stream A: transport context we can cancel. Its Send signals when entered and then blocks until
	// released, which parks A in the send loop so it cannot reach its cleanup until we let it. Its Recv
	// follows the context.
	ctxA, cancelA := context.WithCancel(metadata.NewIncomingContext(t.Context(), md))
	aSendStarted := make(chan struct{}, 1)
	aSendRelease := make(chan struct{})
	aDone := make(chan error, 1)

	streamA := &fakeStream{
		ctx: ctxA,
		recv: func() (*pb.PeerPacket, error) {
			<-ctxA.Done()

			return nil, io.EOF
		},
		send: func(*pb.PeerPacket) error {
			select {
			case aSendStarted <- struct{}{}:
			default:
			}

			<-aSendRelease

			return io.EOF
		},
	}

	go func() { aDone <- svc.CreateStream(streamA) }()

	// Wait until A has installed the peer and its shared send queue.
	require.Eventually(t, func() bool {
		_, ok := pt.GetSendQueue(peerAddr, false)

		return ok
	}, time.Second*2, time.Millisecond, "stream A never installed its queue")

	// Push a packet so A's send loop leaves the Pop and enters Send, then wait until it is actually
	// parked there. Only then is it deterministic that A is past its context check and will not run
	// cleanup until released, so cancelA below cannot make A clean up before B installs.
	q, ok := pt.GetSendQueue(peerAddr, false)
	require.True(t, ok)
	require.NoError(t, q.Push(t.Context(), []byte("park A in Send")))

	select {
	case <-aSendStarted:
	case <-time.After(time.Second * 2):
		t.Fatal("stream A never parked in Send")
	}

	// A's transport closes. Its context cause becomes Canceled, NOT errPeerReplaced, which is the
	// condition the old cause-based cleanup could not tell apart from "not replaced".
	cancelA()

	// Stream B replaces A for the same peer address. It keeps running (Recv/Send block on ctxB).
	ctxB, cancelB := context.WithCancel(metadata.NewIncomingContext(t.Context(), md))
	defer cancelB()

	bStarted := make(chan struct{})
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

	// Wait until B has installed itself (its Recv ran once), so B now owns the peer entry and queue.
	select {
	case <-bStarted:
	case <-time.After(time.Second * 2):
		t.Fatal("stream B never started")
	}

	// Now let A finish: it returns and runs its cleanup. With the fix it sees it no longer owns the
	// entry and leaves B's queue alone. Without the fix it deletes B's queue.
	close(aSendRelease)

	select {
	case <-aDone:
	case <-time.After(time.Second * 2):
		t.Fatal("stream A never returned")
	}

	_, ok = pt.GetSendQueue(peerAddr, false)
	assert.True(t, ok, "the replacement stream's send queue must survive the old stream's cleanup")

	cancelB()

	select {
	case <-bDone:
	case <-time.After(time.Second * 2):
		t.Fatal("stream B never returned")
	}

	// Drain the service's goroutines before returning, so none of them outlive the test.
	svc.Wait()
}
