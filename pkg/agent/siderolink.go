// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package agent

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/siderolabs/siderolink/api/siderolink"
	"github.com/siderolabs/siderolink/internal/server"
	"github.com/siderolabs/siderolink/pkg/wgtunnel/wgbind"
	"github.com/siderolabs/siderolink/pkg/wgtunnel/wggrpc"
	"github.com/siderolabs/siderolink/pkg/wireguard"
)

type sideroLinkConfig struct {
	wireguardEndpoint string
	apiEndpoint       string
	apiTLSConfig      *tls.Config // if not-nil, the API will be served over TLS
	joinToken         string
	predefinedPairs   []bindUUIDtoIPv6
	forceUserspace    bool
}

type bindUUIDtoIPv6 struct {
	IPv6 netip.Addr
	UUID string
}

func sideroLink(ctx context.Context, eg *errgroup.Group, cfg sideroLinkConfig, peerHandler wireguard.PeerHandler, logger *zap.Logger) error {
	lis, err := net.Listen("tcp", cfg.apiEndpoint)
	if err != nil {
		return fmt.Errorf("error listening for gRPC API: %w", err)
	}

	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return fmt.Errorf("error generating key: %w", err)
	}

	grpcEndpointsPrefix := wireguard.VirtualNetworkPrefix()

	nodePrefix := wireguard.NetworkPrefix("")
	serverPrefix := netip.PrefixFrom(nodePrefix.Addr().Next(), nodePrefix.Bits())

	provider, err := newProvider(nodePrefix, cfg.predefinedPairs, logger)
	if err != nil {
		return err
	}

	wireguardEndpoint, err := netip.ParseAddrPort(cfg.wireguardEndpoint)
	if err != nil {
		return fmt.Errorf("invalid Wireguard endpoint: %w", err)
	}

	// After this number the queue "from peers" will block
	const maxPendingClientMessages = 100

	pt := wgbind.NewPeerTraffic(maxPendingClientMessages)
	allowedPeers := wggrpc.NewAllowedPeers()

	p := &peerProvider{
		wrapped:      peerHandler,
		allowedPeers: allowedPeers,
	}

	wgDevice, err := wireguard.NewDevice(
		wireguard.DeviceConfig{
			Bind:                   wgbind.NewServerBind(conn.NewDefaultBind(), grpcEndpointsPrefix, pt, logger),
			PeerHandler:            p,
			Logger:                 logger,
			ServerPrefix:           serverPrefix,
			PrivateKey:             privateKey,
			AutoPeerRemoveInterval: 10 * time.Second,
			ListenPort:             wireguardEndpoint.Port(),
			ForceUserspace:         cfg.forceUserspace,
		},
	)
	if err != nil {
		return fmt.Errorf("error initializing wgDevice: %w", err)
	}

	srv := server.NewServer(server.Config{
		NodeProvisioner: provider,
		ServerAddress:   serverPrefix.Addr(),
		ServerEndpoint:  wireguardEndpoint,
		VirtualPrefix:   grpcEndpointsPrefix,
		JoinToken:       cfg.joinToken,
		ServerPublicKey: privateKey.PublicKey(),
		Logger:          logger,
	})

	s := grpc.NewServer(getCreds(cfg.apiTLSConfig))
	pb.RegisterProvisionServiceServer(s, srv)
	pb.RegisterWireGuardOverGRPCServiceServer(s, wggrpc.NewService(pt, allowedPeers, logger))

	eg.Go(func() error {
		defer wgDevice.Close() //nolint:errcheck

		return wgDevice.Run(ctx, logger, srv)
	})

	stopServer := sync.OnceFunc(s.Stop)

	eg.Go(func() error {
		defer stopServer()

		return s.Serve(lis)
	})

	context.AfterFunc(ctx, stopServer)

	return nil
}

func getCreds(cfg *tls.Config) grpc.ServerOption {
	if cfg != nil {
		return grpc.Creds(credentials.NewTLS(cfg))
	}

	return grpc.Creds(insecure.NewCredentials())
}

type peerProvider struct {
	allowedPeers *wggrpc.AllowedPeers
	wrapped      wireguard.PeerHandler
}

func (p *peerProvider) HandlePeerAdded(event wireguard.PeerEvent) error {
	if event.VirtualAddr.IsValid() {
		p.allowedPeers.AddToken(event.PubKey, event.VirtualAddr.String())
	}

	if p.wrapped == nil {
		return nil
	}

	return p.wrapped.HandlePeerAdded(event)
}

func (p *peerProvider) HandlePeerRemoved(pubKey wgtypes.Key) error {
	p.allowedPeers.RemoveToken(pubKey)

	if p.wrapped == nil {
		return nil
	}

	return p.wrapped.HandlePeerRemoved(pubKey)
}

func newProvider(prefix netip.Prefix, pairs []bindUUIDtoIPv6, logger *zap.Logger) (*uuidIPv6Provider, error) {
	for i, p := range pairs {
		switch {
		case p.UUID == "":
			return nil, fmt.Errorf("empty UUID for pair at index %d", i)

		case !p.IPv6.IsValid():
			return nil, fmt.Errorf("invalid IPv6 address for UUID %s at index %d", p.UUID, i)

		case !p.IPv6.Is6():
			return nil, fmt.Errorf("IPv6 address %q is not an IPv6 address", p.IPv6)

		case !prefix.Contains(p.IPv6):
			return nil, fmt.Errorf("IPv6 address %q is not in the prefix %q", p.IPv6, prefix)
		}

		logger.Info("set predefined UUID=IPv6 pair", zap.String("uuid", p.UUID), zap.Stringer("ipv6", p.IPv6))
	}

	return &uuidIPv6Provider{prefix: prefix, pairs: pairs, logger: logger}, nil
}

//nolint:govet
type uuidIPv6Provider struct {
	prefix netip.Prefix
	pairs  []bindUUIDtoIPv6
	logger *zap.Logger
}

func (u *uuidIPv6Provider) NodePrefix(nodeUUID string, _ string) (netip.Prefix, error) {
	if idx := slices.IndexFunc(u.pairs, func(pair bindUUIDtoIPv6) bool { return pair.UUID == nodeUUID }); idx != -1 {
		u.logger.Info("found predefined IPv6 for UUID", zap.String("uuid", nodeUUID), zap.Stringer("ipv6", u.pairs[idx].IPv6))

		result := netip.PrefixFrom(u.pairs[idx].IPv6, u.prefix.Bits())

		return result, nil
	}

	addr, err := wireguard.GenerateRandomNodeAddr(u.prefix)
	if err != nil {
		return netip.Prefix{}, err
	}

	return addr, nil
}
