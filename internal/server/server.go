// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package server implements a test server for the SideroLink.
package server

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/netip"

	"github.com/siderolabs/go-pointer"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/siderolabs/siderolink/api/siderolink"
	"github.com/siderolabs/siderolink/pkg/wireguard"
)

// Server implents gRPC API.
type Server struct {
	pb.UnimplementedProvisionServiceServer

	eventCh chan wireguard.PeerEvent
	cfg     Config
}

// Config configures the server.
//
//nolint:govet
type Config struct {
	NodePrefix      netip.Prefix
	ServerAddress   netip.Addr
	ServerEndpoint  netip.AddrPort
	VirtualPrefix   netip.Prefix
	JoinToken       string
	ServerPublicKey wgtypes.Key
	Logger          *zap.Logger
}

// NewServer initializes new server.
func NewServer(cfg Config) *Server {
	return &Server{
		cfg:     cfg,
		eventCh: make(chan wireguard.PeerEvent),
	}
}

// EventCh implements the wireguard.PeerSource interface.
func (srv *Server) EventCh() <-chan wireguard.PeerEvent {
	return srv.eventCh
}

// Provision the SideroLink.
func (srv *Server) Provision(_ context.Context, req *pb.ProvisionRequest) (*pb.ProvisionResponse, error) {
	if srv.cfg.JoinToken != "" && (req.JoinToken == nil || *req.JoinToken != srv.cfg.JoinToken) {
		return nil, status.Error(codes.PermissionDenied, "invalid join token")
	}

	// generated random address for the node
	nodeAddress, err := generateRandomNodeAddr(srv.cfg.NodePrefix)
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("error generating node address: %s", err))
	}

	pubKey, err := wgtypes.ParseKey(req.NodePublicKey)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("error parsing Wireguard key: %s", err))
	}

	var virtualNode netip.Prefix

	if req.WireguardOverGrpc != nil && *req.WireguardOverGrpc {
		virtualNode, err = generateRandomNodeAddr(srv.cfg.VirtualPrefix)
		if err != nil {
			return nil, status.Error(codes.Internal, fmt.Sprintf("error generating tunnel endpoint: %s", err))
		}
	}

	srv.eventCh <- wireguard.PeerEvent{
		PubKey:                      pubKey,
		Address:                     nodeAddress.Addr(),
		PersistentKeepAliveInterval: pointer.To(wireguard.RecommendedPersistentKeepAliveInterval),
		VirtualAddr:                 virtualNode.Addr(),
	}

	var (
		grpcPeerAddrPort string
		ep               string
	)

	if virtualNode.IsValid() {
		grpcPeerAddrPort = net.JoinHostPort(virtualNode.Addr().String(), "50888")
		ep = grpcPeerAddrPort
	} else {
		ep = srv.cfg.ServerEndpoint.String()
	}

	srv.cfg.Logger.Debug(
		"got new node",
		zap.String("uuid", req.GetNodeUuid()),
		zap.String("unique_token", req.GetNodeUniqueToken()),
		zap.String("talos_version", req.GetTalosVersion()),
		zap.String("node_public_key", req.GetNodePublicKey()),
		zap.String("node_address", nodeAddress.String()),
		zap.String("server_endpoint", ep),
		zap.String("server_address", srv.cfg.ServerAddress.String()),
	)

	return &pb.ProvisionResponse{
		ServerEndpoint:    pb.MakeEndpoints(ep),
		ServerPublicKey:   srv.cfg.ServerPublicKey.String(),
		NodeAddressPrefix: nodeAddress.String(),
		ServerAddress:     srv.cfg.ServerAddress.String(),
		GrpcPeerAddrPort:  grpcPeerAddrPort,
	}, nil
}

func generateRandomNodeAddr(prefix netip.Prefix) (netip.Prefix, error) {
	raw := prefix.Addr().As16()
	salt := make([]byte, 8)

	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return netip.Prefix{}, err
	}

	copy(raw[8:], salt)

	return netip.PrefixFrom(netip.AddrFrom16(raw), prefix.Bits()), nil
}
