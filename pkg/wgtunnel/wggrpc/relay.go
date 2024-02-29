// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package wggrpc provides a WireGuard over GRPC client and server implementation.
package wggrpc

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	pb "github.com/siderolabs/siderolink/api/siderolink"
	"github.com/siderolabs/siderolink/internal/wait"
	"github.com/siderolabs/siderolink/pkg/openclose"
	"github.com/siderolabs/siderolink/pkg/wgtunnel/wgbind"
)

// PeerAddrKey is the key used to store the peer address in the grpc context.
const PeerAddrKey = "x-siderolink-ipv6-addr"

// NewRelayToHost creates a new [Relay].
func NewRelayToHost(host string, retryTimeout time.Duration, queues *wgbind.QueuePair, ourAddr netip.AddrPort, opts ...grpc.DialOption) (*Relay, error) {
	switch {
	case host == "":
		return nil, errors.New("host must be non-empty")
	case retryTimeout < time.Second:
		return nil, errors.New("retry timeout must be at least 1 second")
	case !ourAddr.IsValid():
		return nil, errors.New("our address must be non-empty")
	}

	conn, err := grpc.Dial(host, opts...)
	if err != nil {
		return nil, err
	}

	return &Relay{
		conn:         conn,
		retryTimeout: retryTimeout,
		queues:       queues,
		ourAddr:      ourAddr,
		ownConn:      true,
	}, nil
}

// NewRelay creates a new [Relay].
func NewRelay(conn *grpc.ClientConn, retryTimeout time.Duration, queues *wgbind.QueuePair, ourAddr netip.AddrPort) *Relay {
	switch {
	case retryTimeout < time.Second:
		panic(errors.New("retry timeout must be at least 1 second"))
	case !ourAddr.IsValid():
		panic(errors.New("our address must be non-empty"))
	}

	return &Relay{
		conn:         conn,
		retryTimeout: retryTimeout,
		queues:       queues,
		ourAddr:      ourAddr,
	}
}

// Relay is the client side of the WireGuard over GRPC relay.
//
//nolint:govet
type Relay struct {
	conn         *grpc.ClientConn
	retryTimeout time.Duration
	queues       *wgbind.QueuePair
	ourAddr      netip.AddrPort
	openClose    openclose.OpenClose
	ownConn      bool
	cancelFn     context.CancelFunc
}

type clientWaitValue = wait.Value[pb.WireGuardOverGRPCService_CreateStreamClient]

// Run runs the [Relay]. It consumes and sends packets from|to the [*QueuePair].
func (r *Relay) Run(ctx context.Context, logger *zap.Logger) error {
	ok, closeFn := r.openClose.Open(func() {
		ctx, r.cancelFn = context.WithCancel(ctx)
	})
	if !ok {
		return errors.New("relay already running/closed")
	}

	defer func() {
		r.cancelFn()

		closeFn()
	}()

	var (
		wv       clientWaitValue
		remoteEp wait.Value[string]
	)

	eg, ctx := errgroup.WithContext(ctx)

	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs(PeerAddrKey, r.ourAddr.String()))

	eg.Go(func() error { return r.runToPeer(ctx, &wv, &remoteEp, logger) })
	eg.Go(func() error { return r.runFromPeer(ctx, &wv, &remoteEp, logger) })

	return eg.Wait()
}

// Close closes the [Relay].
func (r *Relay) Close() {
	if r == nil {
		return
	}

	r.openClose.RequestCloseWait(func() {
		if r.cancelFn != nil {
			r.cancelFn()
		}

		if r.ownConn {
			r.conn.Close() //nolint:errcheck
		}
	})
}

// IsClosed returns true if the [Relay] is closed.
func (r *Relay) IsClosed() bool {
	return r == nil || r.openClose.IsClosed()
}

func (r *Relay) runToPeer(ctx context.Context, wv *clientWaitValue, remoteEp *wait.Value[string], logger *zap.Logger) error {
	for {
		stream, ok := wv.TryGet()
		if !ok {
			remoteEp.Unset()

			var err error

			stream, err = pb.NewWireGuardOverGRPCServiceClient(r.conn).CreateStream(ctx)
			if err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return nil
				}

				if errors.Is(err, errPeerReplaced) || errors.Is(err, errPeerNotAllowed) {
					return err
				}

				logger.Debug("client failed to create stream", zap.Error(err))

				select {
				case <-time.NewTimer(r.retryTimeout).C:
					continue
				case <-ctx.Done():
					return nil
				}
			}

			logger.Debug("client opened stream")

			wv.Set(stream)
		}

		pop, err := r.queues.ToPeer.Pop(ctx)
		if err != nil {
			return nil //nolint:nilerr
		}

		if !ok {
			remoteEp.Set(pop.Addr)
		}

		l := logger.With(zap.String("dst", pop.Addr), zap.Int("len", len(pop.Data)))

		l.Debug("client sending packet to peer")

		if err = stream.Send(&pb.PeerPacket{
			Data: pop.Data,
		}); err != nil {
			if errors.Is(err, errPeerReplaced) || errors.Is(err, errPeerNotAllowed) {
				return err
			}

			continue
		}

		logger.Debug("client sent packet to peer")
	}
}

func (r *Relay) runFromPeer(ctx context.Context, wv *clientWaitValue, remoteEp *wait.Value[string], logger *zap.Logger) error {
	for {
		stream, err := wv.Get(ctx)
		if err != nil {
			return nil //nolint:nilerr
		}

		recv, err := stream.Recv()
		if err != nil {
			wv.Unset()

			if errors.Is(err, errPeerReplaced) || errors.Is(err, errPeerNotAllowed) {
				return err
			}

			continue
		}

		src, err := remoteEp.Get(ctx)
		if err != nil {
			return nil //nolint:nilerr
		}

		l := logger.With(zap.String("src", src), zap.Int("len", len(recv.Data)))

		l.Debug("client got server message")

		if err = r.queues.FromPeer.Push(ctx, wgbind.Packet{
			Addr: src,
			Data: recv.Data,
		}); err != nil {
			wv.Unset()

			continue
		}

		l.Debug("client pushed server message")
	}
}
