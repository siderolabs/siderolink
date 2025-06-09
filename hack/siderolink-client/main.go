// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package siderolink-client provides basic implementation of a client for the SideroLink service over GRPC.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"runtime/pprof"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/siderolabs/gen/ensure"
	"github.com/siderolabs/gen/panicsafe"
	"github.com/siderolabs/gen/xslices"
	"github.com/siderolabs/go-pointer"
	"go.uber.org/zap"
	"go4.org/netipx"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/siderolabs/siderolink/api/siderolink"
	"github.com/siderolabs/siderolink/pkg/wgtunnel"
	"github.com/siderolabs/siderolink/pkg/wgtunnel/wgbind"
	"github.com/siderolabs/siderolink/pkg/wgtunnel/wggrpc"
	"github.com/siderolabs/siderolink/pkg/wireguard"
)

var opts struct {
	dest string
}

func main() {
	flag.StringVar(&opts.dest, "dest", "", "grpc endpoint")

	flag.Parse()

	if opts.dest == "" {
		fmt.Fprintln(os.Stderr, "dest is required")

		flag.PrintDefaults()

		os.Exit(1)
	}

	for {
		if err := app(); err != nil {
			fmt.Fprintln(os.Stderr, "error is", err)

			pprof.Lookup("goroutine").WriteTo(os.Stdout, 1)

			os.Exit(1)
		}

		break
	}
}

func app() error {
	logger, err := zap.NewDevelopment()
	if err != nil {
		return fmt.Errorf("error creating logger: %w", err)
	}

	ctx, cancel := notifyContextCause(context.Background(), os.Interrupt)
	defer cancel(nil)

	queuePair := wgbind.NewQueuePair(100, 100)

	device, err := wgtunnel.NewTunnelDevice(wireguard.InterfaceName, wireguard.LinkMTU, queuePair, logger)
	if err != nil {
		return fmt.Errorf("failed to create tunnel device: %w", err)
	}

	go func() {
		if runErr := panicsafe.Run(func() {
			cancel(device.Run())
		}); runErr != nil {
			logger.Error("error running tunnel device", zap.Error(runErr))
		}
	}()

	defer closeClosable(device.Close, "tunnel device", logger)

	ctrl := &mxCtrl{
		ctrl: ensure.Value(wgctrl.New()),
	}

	defer closeClosableErr(ctrl.Close, "wireguard controller", logger)

	ifaceName := device.IfaceName()

	if err = ifaceUP(ifaceName); err != nil {
		return err
	}

	logger.Info("wireguard device link up", zap.String("interface", ifaceName))

	go func() {
		if monitorErr := panicsafe.RunErr(func() error {
			return monitorPeers(ctx, ctrl, ifaceName, logger)
		}); monitorErr != nil {
			logger.Error("peer monitoring failed", zap.Error(monitorErr))

			cancel(monitorErr)
		}
	}()

	for {
		if err := run(ctx, ctrl, ifaceName, queuePair, logger); err != nil {
			return err
		}
	}
}

type wgCtrl interface {
	ConfigureDevice(name string, cfg wgtypes.Config) error
	Device(name string) (*wgtypes.Device, error)
	Close() error
}

func run(ctx context.Context, ctrl wgCtrl, ifaceName string, queuePair *wgbind.QueuePair, logger *zap.Logger) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	conn := ensure.Value(grpc.Dial(opts.dest, grpc.WithTransportCredentials(insecure.NewCredentials())))
	defer closeClosableErr(conn.Close, "grpc connection", logger)

	key := ensure.Value(wgtypes.GeneratePrivateKey())
	clientUUID := uuid.Must(uuid.NewUUID())

	prov, err := provision(ctx, conn, key, clientUUID, logger)
	if err != nil {
		return err
	}

	logger.Info(
		"provisioned",
		zap.String("uuid", clientUUID.String()),
		zap.Stringer("our_public_key", key.PublicKey()),
		zap.String("node_address_prefix", prov.NodeAddressPrefix),
		zap.String("server_address", prov.ServerAddress),
		zap.Strings("server_endpoint", prov.ServerEndpoint),
		zap.String("server_public_key", prov.ServerPublicKey),
		zap.String("grpc_peer_addr", prov.GrpcPeerAddrPort),
	)

	nodeAddressPrefix := ensure.Value(netip.ParsePrefix(prov.NodeAddressPrefix))

	ipRemover, err := wireguard.SetupIPToInterface(nodeAddressPrefix, ifaceName)
	if err != nil {
		return fmt.Errorf("error setting up IP to interface: %w", err)
	}

	defer closeClosableErr(ipRemover, "added ip", logger)

	logger.Info(
		"tun device set up",
		zap.String("interface", ifaceName),
		zap.Stringer("prefix", nodeAddressPrefix),
	)

	serverPrefix := netip.PrefixFrom(ensure.Value(netip.ParseAddr(prov.ServerAddress)), 128)
	ipNet := netipx.PrefixIPNet(serverPrefix)
	remoteEndpoint := ensure.Value(net.ResolveUDPAddr("udp", prov.GrpcPeerAddrPort))

	logger.Info("attempting to configure wireguard device", zap.Stringer("remote_peer_prefix", ipNet))

	serverPublicKey := ensure.Value(wgtypes.ParseKey(prov.ServerPublicKey))

	cfg := wgtypes.Config{
		PrivateKey: &key,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:                   serverPublicKey,
				Endpoint:                    remoteEndpoint,
				PersistentKeepaliveInterval: pointer.To(25 * time.Second),
				ReplaceAllowedIPs:           true,
				AllowedIPs: []net.IPNet{
					*ipNet,
				},
			},
		},
	}

	err = ctrl.ConfigureDevice(ifaceName, cfg)
	if err != nil {
		return fmt.Errorf("failed to configure Wireguard device: %w", err)
	}

	logger.Info("wireguard device set up", zap.String("interface", ifaceName), zap.Stringer("address", nodeAddressPrefix))

	relay, err := wggrpc.NewRelayToHost(opts.dest, 5*time.Second, queuePair, remoteEndpoint.AddrPort(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("failed to create relay: %w", err)
	}

	defer closeClosable(relay.Close, "relay", logger)

	go func() {
		if runErr := panicsafe.Run(func() {
			cancel(relay.Run(ctx, logger))
		}); runErr != nil {
			logger.Error("error running relay", zap.Error(runErr))
		}
	}()

	for {
		select {
		case <-ctx.Done():
			err := context.Cause(ctx)
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}

			logger.Info("retryable error", zap.Error(err))

			return nil

		case <-time.After(5 * time.Second):
			device, err := ctrl.Device(ifaceName)
			if err != nil {
				return fmt.Errorf("failed to get the device data: %w", err)
			}

			idx := slices.IndexFunc(device.Peers, func(peer wgtypes.Peer) bool { return peer.PublicKey == serverPublicKey })
			if idx == -1 {
				return nil
			}

			logger.Info("our server key still exists")
		}
	}
}

func monitorPeers(ctx context.Context, ctrl wgCtrl, ifaceName string, logger *zap.Logger) error {
	logger.Info("monitoring peers")

	for {
		select {
		case <-ctx.Done():
			return nil

		case <-time.After(5 * time.Second):
			logger.Debug("checking peers for device", zap.String("interface", ifaceName))

			dev, err := ctrl.Device(ifaceName)
			if err != nil {
				return fmt.Errorf("failed to get device: %w", err)
			}

			for _, peer := range dev.Peers {
				logger.Debug(
					"peer",
					zap.String("public_key", peer.PublicKey.String()),
					zap.String("endpoint", peer.Endpoint.String()),
					zap.Duration("last_handshake", time.Since(peer.LastHandshakeTime)),
				)
			}

			downedPeers := xslices.Filter(dev.Peers, func(p wgtypes.Peer) bool {
				return !p.LastHandshakeTime.IsZero() && time.Since(p.LastHandshakeTime) > wireguard.PeerDownInterval
			})

			toRemove := xslices.Map(downedPeers, func(p wgtypes.Peer) wgtypes.PeerConfig {
				return wgtypes.PeerConfig{
					PublicKey: p.PublicKey,
					Remove:    true,
					Endpoint:  p.Endpoint,
				}
			})

			for _, peer := range toRemove {
				logger.Info("removing peer", zap.String("public_key", peer.PublicKey.String()), zap.String("endpoint", peer.Endpoint.String()))
			}

			if err = ctrl.ConfigureDevice(ifaceName, wgtypes.Config{Peers: toRemove}); err != nil {
				return fmt.Errorf("failed to remove peers: %w", err)
			}
		}
	}
}

func ifaceUP(ifaceName string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("error finding interface: %w", err)
	}

	err = wireguard.LinkUp(iface)
	if err != nil {
		return fmt.Errorf("error bringing link up: %w", err)
	}

	return nil
}

func notifyContextCause(ctx context.Context, sigs ...os.Signal) (context.Context, context.CancelCauseFunc) {
	ctx, cancel := context.WithCancelCause(ctx)

	ctx, sigCancel := signal.NotifyContext(ctx, sigs...)

	return ctx, func(cause error) {
		cancel(cause)

		sigCancel()
	}
}

func closeClosable(closeable func(), name string, logger *zap.Logger) {
	closeClosableErr(func() error {
		closeable()
		return nil
	}, name, logger)
}

func closeClosableErr(closeable func() error, name string, logger *zap.Logger) {
	logger.Info("closing " + name)

	if err := closeable(); err != nil {
		logger.Error("error closing "+name, zap.Error(err))
	} else {
		logger.Info("closed " + name)
	}
}

func provision(ctx context.Context, conn *grpc.ClientConn, key wgtypes.Key, clientUUID uuid.UUID, logger *zap.Logger) (*pb.ProvisionResponse, error) {
	client := pb.NewProvisionServiceClient(conn)

	for {
		prov, err := client.Provision(ctx, &pb.ProvisionRequest{
			NodeUuid:          clientUUID.String(),
			NodePublicKey:     key.PublicKey().String(),
			JoinToken:         pointer.To("foo"),
			NodeUniqueToken:   pointer.To("random-token"),
			TalosVersion:      pointer.To("v1.7.0-alpha.0"),
			WireguardOverGrpc: pointer.To(true),
		})
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, fmt.Errorf("failed to provision: %w", err)
			}

			logger.Warn("provision failed, retrying in 10 seconds", zap.Error(err))

			select {
			case <-time.After(10 * time.Second):
				continue
			case <-ctx.Done():
				return nil, context.Cause(ctx)
			}
		}

		return prov, nil
	}
}

type mxCtrl struct {
	ctrl *wgctrl.Client
	mx   sync.Mutex
}

func (m *mxCtrl) ConfigureDevice(name string, cfg wgtypes.Config) error {
	m.mx.Lock()
	defer m.mx.Unlock()

	return m.ctrl.ConfigureDevice(name, cfg)
}

func (m *mxCtrl) Device(name string) (*wgtypes.Device, error) {
	m.mx.Lock()
	defer m.mx.Unlock()

	return m.ctrl.Device(name)
}

func (m *mxCtrl) Close() error {
	m.mx.Lock()
	defer m.mx.Unlock()

	return m.ctrl.Close()
}
