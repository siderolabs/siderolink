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

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"inet.af/netaddr"

	pb "github.com/talos-systems/siderolink/api/siderolink"
	"github.com/talos-systems/siderolink/pkg/wireguard"
)

// Server implents gRPC API.
type Server struct {
	pb.UnimplementedProvisionServiceServer

	eventCh chan wireguard.PeerEvent
	cfg     Config
}

// Config configures the server.
type Config struct {
	NodePrefix      netaddr.IPPrefix
	ServerAddress   netaddr.IP
	ServerEndpoint  netaddr.IPPort
	JoinToken       string
	ServerPublicKey wgtypes.Key
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
func (srv *Server) Provision(ctx context.Context, req *pb.ProvisionRequest) (*pb.ProvisionResponse, error) {
	if srv.cfg.JoinToken != "" && (req.JoinToken == nil || *req.JoinToken != srv.cfg.JoinToken) {
		return nil, status.Error(codes.PermissionDenied, "invalid join token")
	}

	// generated random address for the node
	raw := srv.cfg.NodePrefix.IP().As16()
	salt := make([]byte, 8)

	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, err
	}

	copy(raw[8:], salt)

	nodeAddress := netaddr.IPPrefixFrom(netaddr.IPFrom16(raw), srv.cfg.NodePrefix.Bits())

	pubKey, err := wgtypes.ParseKey(req.NodePublicKey)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("error parsing Wireguard key: %s", err))
	}

	srv.eventCh <- wireguard.PeerEvent{
		PubKey:  pubKey,
		Address: nodeAddress.IP(),
	}

	return &pb.ProvisionResponse{
		ServerEndpoint:    srv.cfg.ServerEndpoint.String(),
		ServerPublicKey:   srv.cfg.ServerPublicKey.String(),
		ServerAddress:     srv.cfg.ServerAddress.String(),
		NodeAddressPrefix: nodeAddress.String(),
	}, nil
}
