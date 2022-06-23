// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"context"
	"fmt"
	"net"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"inet.af/netaddr"

	pb "github.com/talos-systems/siderolink/api/siderolink"
	"github.com/talos-systems/siderolink/internal/server"
	"github.com/talos-systems/siderolink/pkg/wireguard"
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

	nodePrefix := wireguard.NetworkPrefix("")
	serverAddr := netaddr.IPPrefixFrom(nodePrefix.IP().Next(), nodePrefix.Bits())

	wireguardEndpoint, err := netaddr.ParseIPPort(sideroLinkFlags.wireguardEndpoint)
	if err != nil {
		return fmt.Errorf("invalid Wireguard endpoint: %w", err)
	}

	wgDevice, err := wireguard.NewDevice(serverAddr, privateKey, wireguardEndpoint.Port(),
		sideroLinkFlags.forceUserspace, logger)
	if err != nil {
		return fmt.Errorf("error initializing wgDevice: %w", err)
	}

	srv := server.NewServer(server.Config{
		NodePrefix:      nodePrefix,
		ServerAddress:   serverAddr.IP(),
		ServerEndpoint:  wireguardEndpoint,
		ServerPublicKey: privateKey.PublicKey(),
		JoinToken:       sideroLinkFlags.joinToken,
	})

	s := grpc.NewServer()
	pb.RegisterProvisionServiceServer(s, srv)

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
