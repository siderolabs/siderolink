// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"

	pb "github.com/siderolabs/siderolink/api/siderolink"
	"github.com/siderolabs/siderolink/internal/server"
	"github.com/siderolabs/siderolink/pkg/wgtunnel/wgbind"
	"github.com/siderolabs/siderolink/pkg/wgtunnel/wggrpc"
	"github.com/siderolabs/siderolink/pkg/wireguard"
)

var sideroLinkFlags struct {
	wireguardEndpoint string
	apiEndpoint       string
	joinToken         string
	forceUserspace    bool
}

func sideroLink(ctx context.Context, eg *errgroup.Group, logger *zap.Logger) error {
	lis, err := net.Listen("tcp", sideroLinkFlags.apiEndpoint)
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

	wireguardEndpoint, err := netip.ParseAddrPort(sideroLinkFlags.wireguardEndpoint)
	if err != nil {
		return fmt.Errorf("invalid Wireguard endpoint: %w", err)
	}

	// After this number the queue "from peers" will block
	const maxPendingClientMessages = 100

	pt := wgbind.NewPeerTraffic(maxPendingClientMessages)
	allowedPeers := wggrpc.NewAllowedPeers()

	p := &peerProvider{
		allowedPeers: allowedPeers,
	}

	wgDevice, err := wireguard.NewDevice(
		wireguard.DeviceConfig{
			PrivateKey:             privateKey,
			ServerPrefix:           serverPrefix,
			ListenPort:             wireguardEndpoint.Port(),
			Bind:                   wgbind.NewServerBind(conn.NewDefaultBind(), grpcEndpointsPrefix, pt, logger),
			AutoPeerRemoveInterval: 10 * time.Second,
			PeerHandler:            p,
			Logger:                 logger,
		},
	)
	if err != nil {
		return fmt.Errorf("error initializing wgDevice: %w", err)
	}

	srv := server.NewServer(server.Config{
		NodePrefix:      nodePrefix,
		ServerAddress:   serverPrefix.Addr(),
		ServerEndpoint:  wireguardEndpoint,
		VirtualPrefix:   grpcEndpointsPrefix,
		JoinToken:       sideroLinkFlags.joinToken,
		ServerPublicKey: privateKey.PublicKey(),
		Logger:          logger,
	})

	s := grpc.NewServer()
	pb.RegisterProvisionServiceServer(s, srv)
	pb.RegisterWireGuardOverGRPCServiceServer(s, wggrpc.NewService(pt, allowedPeers, logger))

	eg.Go(func() error {
		defer wgDevice.Close() //nolint:errcheck

		return wgDevice.Run(ctx, logger, srv)
	})

	eg.Go(func() error {
		return s.Serve(lis)
	})

	eg.Go(func() error {
		<-ctx.Done()

		s.Stop()

		return nil
	})

	return nil
}

type peerProvider struct {
	allowedPeers *wggrpc.AllowedPeers
}

func (p *peerProvider) HandlePeerAdded(pubKey wgtypes.Key, virtualIP netip.Addr) error {
	p.allowedPeers.AddToken(pubKey, virtualIP.String())

	return nil
}

func (p *peerProvider) HandlePeerRemoved(pubKey wgtypes.Key) error {
	p.allowedPeers.RemoveToken(pubKey)

	return nil
}
