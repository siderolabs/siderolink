// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package wggrpc

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"github.com/siderolabs/gen/panicsafe"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/siderolabs/siderolink/api/siderolink"
	"github.com/siderolabs/siderolink/pkg/wgtunnel/wgbind"
)

// NewService creates a new WireGuard over GRPC service.
func NewService(pt *wgbind.PeerTraffic, allowed *AllowedPeers, logger *zap.Logger) *Service {
	return &Service{
		pt:      pt,
		allowed: allowed,
		logger:  logger,
		m:       map[string]context.CancelCauseFunc{},
	}
}

// Service is the gRPC service responsible for handling WireGuard over GRPC traffic.
//
//nolint:govet
type Service struct {
	pb.UnimplementedWireGuardOverGRPCServiceServer

	pt      *wgbind.PeerTraffic
	allowed *AllowedPeers

	logger *zap.Logger
	mx     sync.Mutex
	m      map[string]context.CancelCauseFunc

	wg sync.WaitGroup
}

// CreateStream implements [pb.WireGuardOverGRPCServiceServer].
func (s *Service) CreateStream(srv pb.WireGuardOverGRPCService_CreateStreamServer) error {
	s.wg.Add(1)
	defer s.wg.Done()

	peerAddr, err := s.getPeerAddr(srv.Context())
	if err != nil {
		return err
	}

	addrPort, err := netip.ParseAddrPort(peerAddr)
	if err != nil {
		s.logger.Debug("incorrect peer address format", zap.Error(err), zap.String("peerAddr", peerAddr))

		return fmt.Errorf("incorrect header value %q: %w", peerAddr, err)
	}

	if !s.allowed.CheckToken(addrPort.Addr().String()) {
		s.logger.Warn("peer address is not allowed", zap.String("peerAddr", peerAddr))

		return errPeerNotAllowed
	}

	s.mx.Lock()
	// If there is existing peer with the same address, cancel it so the other goroutine can exit.
	if cancel, ok := s.m[peerAddr]; ok {
		cancel(errPeerReplaced)
	}

	ctx, cancel := context.WithCancelCause(srv.Context())
	defer cancel(nil)

	s.m[peerAddr] = cancel

	queue, _ := s.pt.GetSendQueue(peerAddr, true)

	s.mx.Unlock()

	defer func() {
		s.mx.Lock()
		if !errors.Is(context.Cause(ctx), errPeerReplaced) {
			delete(s.m, peerAddr)

			s.pt.RemoveQueue(peerAddr)
		}
		s.mx.Unlock()
	}()

	eg, ctx := errgroup.WithContext(ctx)

	l := s.logger.With(zap.String("peer", peerAddr))

	eg.Go(panicsafe.RunErrF(func() error {
		s.wg.Add(1)
		defer s.wg.Done()

		for {
			packet, err := srv.Recv()
			if err != nil {
				l.Debug("service failed to receive packet", zap.Error(err))

				return handleReturn(ctx, err)
			}

			l.Debug("service received packet from peer", zap.Int("len", len(packet.Data)))

			err = s.pt.PushRecvData(ctx, wgbind.ReceiveData{Addr: peerAddr, Packet: packet})
			if err != nil {
				l.Debug("service failed to push packet to queue", zap.Error(err))

				return handleReturn(ctx, err)
			}

			l.Debug("service pushed packet to peer queue", zap.Int("len", len(packet.Data)))
		}
	}))

	for {
		select {
		case <-ctx.Done():
			l.Debug("service context done")

			return handleReturn(ctx, ctx.Err())
		default:
		}

		data, err := queue.Pop(ctx)
		if err != nil {
			l.Debug("service failed to pop outgoing packet from queue", zap.Error(err))

			return handleReturn(ctx, err)
		}

		l.Debug("service preparing outgoing packet from queue", zap.Int("len", len(data)))

		err = srv.Send(&pb.PeerPacket{Data: data})
		if err != nil {
			l.Debug("service failed to send packet to peer", zap.Error(err))

			return handleReturn(ctx, err)
		}

		l.Debug("service sent outgoing packet to peer", zap.Int("len", len(data)))
	}
}

func (s *Service) getPeerAddr(ctx context.Context) (string, error) {
	incomingContext, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		s.logger.Debug("service failed to get metadata from context")

		return "", errors.New("failed to get metadata from context")
	}

	peerAddrs, ok := incomingContext[PeerAddrKey]
	if !ok || len(peerAddrs) == 0 {
		s.logger.Debug("service failed to get peer address from context")

		return "", errors.New("failed to get peer address from context")
	}

	return peerAddrs[0], nil
}

// Wait waits for all the service goroutines to finish.
func (s *Service) Wait() {
	s.wg.Wait()
}

func handleReturn(ctx context.Context, err error) error {
	cause := context.Cause(ctx)
	if errors.Is(cause, errPeerReplaced) {
		return errPeerReplaced
	}

	return err
}

// NewAllowedPeers creates a new allowed peers list.
func NewAllowedPeers() *AllowedPeers {
	return &AllowedPeers{
		allowed:       map[wgtypes.Key]string{},
		allowedTokens: map[string]struct{}{},
	}
}

// AllowedPeers is a list of allowed peers. Currently, [PeerAddrKey] netip.Addr value is used as a token.
//
//nolint:govet
type AllowedPeers struct {
	mx            sync.RWMutex
	allowed       map[wgtypes.Key]string
	allowedTokens map[string]struct{}
}

// CheckToken checks if the token is allowed.
func (p *AllowedPeers) CheckToken(token string) bool {
	p.mx.RLock()
	defer p.mx.RUnlock()

	_, ok := p.allowedTokens[token]

	return ok
}

// AddToken adds the peer to the allowed list.
func (p *AllowedPeers) AddToken(pubKey wgtypes.Key, token string) {
	p.mx.Lock()
	defer p.mx.Unlock()

	p.allowed[pubKey] = token
	p.allowedTokens[token] = struct{}{}
}

// RemoveToken removes the peer from the allowed list.
func (p *AllowedPeers) RemoveToken(pubKey wgtypes.Key) {
	p.mx.Lock()
	defer p.mx.Unlock()

	key, ok := p.allowed[pubKey]
	if !ok {
		return
	}

	delete(p.allowed, pubKey)
	delete(p.allowedTokens, key)
}

var (
	errPeerReplaced   = status.Error(codes.Aborted, "peer replaced")
	errPeerNotAllowed = status.Error(codes.PermissionDenied, "peer not allowed")
)
