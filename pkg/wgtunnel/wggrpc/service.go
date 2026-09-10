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
		m:       map[wgtypes.Key]*streamHandle{},
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
	m      map[wgtypes.Key]*streamHandle

	wg sync.WaitGroup
}

// streamHandle identifies a single CreateStream call for a peer. It is stored by pointer so a stream
// can tell whether it still owns the peer's map entry: a replacement installs its own handle, and the
// departing stream must not tear down the peer state the replacement now owns.
type streamHandle struct {
	cancel context.CancelCauseFunc
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

	s.mx.Lock()

	// The address the peer presents is only a credential: it is reassigned on every re-provisioning,
	// so the public key behind it is what identifies the peer from here on. It is resolved under the
	// same lock that installs the stream, so a token revoked or handed to another peer in between
	// cannot admit a stream under an identity it no longer has.
	pubKey, ok := s.allowed.PubKeyForToken(addrPort.Addr().String())
	if !ok {
		s.mx.Unlock()

		s.logger.Warn("peer address is not allowed", zap.String("peerAddr", peerAddr))

		return errPeerNotAllowed
	}

	// If there is an existing stream for the same peer, cancel it so the other goroutine can exit. The
	// peer is keyed by public key and not by address, so a peer that comes back on a new address still
	// displaces its own stale stream instead of running alongside it.
	if existing, ok := s.m[pubKey]; ok {
		existing.cancel(errPeerReplaced)
	}

	ctx, cancel := context.WithCancelCause(srv.Context())
	defer cancel(nil)

	handle := &streamHandle{cancel: cancel}
	s.m[pubKey] = handle

	sendQueue, displaced, hasDisplaced := s.pt.OpenSession(pubKey, addrPort)
	if hasDisplaced {
		// The address was handed over to this peer from another one, and that peer's session is gone
		// now. Its stream must go too, or it would keep running detached from any session.
		if existing, ok := s.m[displaced]; ok {
			existing.cancel(errPeerReplaced)
			delete(s.m, displaced)
		}
	}

	s.mx.Unlock()

	defer func() {
		s.mx.Lock()
		// Only tear down the peer state if this stream still owns it. A replacement stream may have
		// taken over the entry and the shared send queue, and it does so even when this stream's
		// context was already canceled by its own transport (so the replaced-cause is not observable
		// here). Ownership by identity is the reliable signal.
		if s.m[pubKey] == handle {
			delete(s.m, pubKey)

			s.pt.CloseSession(pubKey)
		}
		s.mx.Unlock()
	}()

	eg, ctx := errgroup.WithContext(ctx)

	l := s.logger.With(zap.String("peer", peerAddr), zap.Stringer("public_key", pubKey))

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

			err = s.pt.PushRecvData(ctx, pubKey, packet)
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

		data, err := sendQueue.Pop(ctx)
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
		allowedTokens: map[string]wgtypes.Key{},
	}
}

// AllowedPeers is a list of allowed peers. Currently, [PeerAddrKey] netip.Addr value is used as a token.
//
// The mapping is kept 1:1 in both directions: a peer has exactly one token, and a token belongs to
// exactly one peer.
//
//nolint:govet
type AllowedPeers struct {
	mx            sync.RWMutex
	allowed       map[wgtypes.Key]string
	allowedTokens map[string]wgtypes.Key
}

// CheckToken checks if the token is allowed.
func (p *AllowedPeers) CheckToken(token string) bool {
	_, ok := p.PubKeyForToken(token)

	return ok
}

// PubKeyForToken returns the public key of the peer the token belongs to.
func (p *AllowedPeers) PubKeyForToken(token string) (wgtypes.Key, bool) {
	p.mx.RLock()
	defer p.mx.RUnlock()

	pubKey, ok := p.allowedTokens[token]

	return pubKey, ok
}

// AddToken adds the peer to the allowed list, replacing the token it had before.
func (p *AllowedPeers) AddToken(pubKey wgtypes.Key, token string) {
	p.mx.Lock()
	defer p.mx.Unlock()

	// A re-provisioned peer is handed a new token, and the one it used before must stop being
	// accepted: otherwise the peer's stale connection stays authorized and keeps competing with the
	// current one.
	if oldToken, ok := p.allowed[pubKey]; ok && oldToken != token {
		delete(p.allowedTokens, oldToken)
	}

	if oldPubKey, ok := p.allowedTokens[token]; ok && oldPubKey != pubKey {
		delete(p.allowed, oldPubKey)
	}

	p.allowed[pubKey] = token
	p.allowedTokens[token] = pubKey
}

// RemoveToken removes the peer from the allowed list.
func (p *AllowedPeers) RemoveToken(pubKey wgtypes.Key) {
	p.mx.Lock()
	defer p.mx.Unlock()

	token, ok := p.allowed[pubKey]
	if !ok {
		return
	}

	delete(p.allowed, pubKey)
	delete(p.allowedTokens, token)
}

var (
	errPeerReplaced   = status.Error(codes.Aborted, "peer replaced")
	errPeerNotAllowed = status.Error(codes.PermissionDenied, "peer not allowed")
)
