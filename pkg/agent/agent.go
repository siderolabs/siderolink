// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package agent provides the main entrypoint for the agent.
package agent

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/siderolabs/siderolink/pkg/wireguard"
)

// Config is the configuration for the agent.
//
//nolint:govet
type Config struct {
	WireguardEndpoint string   // WireguardEndpoint is the endpoint for the Wireguard server.
	APIEndpoint       string   // APIEndpoint is the gRPC endpoint for the SideroLink API.
	JoinToken         string   // JoinToken is the join token for the SideroLink API.
	ForceUserspace    bool     // ForceUserspace forces the usage of the userspace UDP device for Wireguard.
	SinkEndpoint      string   // SinkEndpoint is the gRPC endpoint for the event sink.
	LogEndpoint       string   // LogEndpoint is the TCP log receiver endpoint.
	UUIDIPv6Pairs     []string // UUIDIPv6Pairs is a list of UUIDs=IPv6 addrs for the nodes.
}

// Run runs the agent. [wireguard.PeerHandler] can be nil.
func Run(ctx context.Context, cfg Config, peerHandler wireguard.PeerHandler, logger *zap.Logger) error {
	eg, ctx := errgroup.WithContext(ctx)

	var normalExit bool

	defer func() {
		if normalExit {
			return
		}

		if waitErr := eg.Wait(); waitErr != nil {
			logger.Error("Wait() failed", zap.Error(waitErr))
		}
	}()

	logger.Info("starting agent",
		zap.String("wireguard_endpoint", cfg.WireguardEndpoint),
		zap.String("api_endpoint", cfg.APIEndpoint),
		zap.String("sink_endpoint", cfg.SinkEndpoint),
		zap.String("log_endpoint", cfg.LogEndpoint),
		zap.Bool("force_userspace", cfg.ForceUserspace),
	)

	runErr := run(ctx, cfg, peerHandler, eg, logger)
	waitErr := eg.Wait()

	normalExit = true

	if waitErr != nil {
		if runErr == nil {
			return waitErr
		}

		return fmt.Errorf("%w; also Wait() failed with: %w", runErr, waitErr)
	}

	return runErr
}

func run(ctx context.Context, cfg Config, peerHandler wireguard.PeerHandler, eg *errgroup.Group, logger *zap.Logger) (runErr error) {
	bindPairs, err := parsePairs(cfg.UUIDIPv6Pairs)
	if err != nil {
		return err
	}

	linkCfg := sideroLinkConfig{
		wireguardEndpoint: cfg.WireguardEndpoint,
		apiEndpoint:       cfg.APIEndpoint,
		joinToken:         cfg.JoinToken,
		forceUserspace:    cfg.ForceUserspace,
		predefinedPairs:   bindPairs,
	}

	if err := sideroLink(ctx, eg, linkCfg, peerHandler, logger); err != nil {
		return fmt.Errorf("SideroLink: %w", err)
	}

	if err := eventSink(ctx, cfg.SinkEndpoint, eg); err != nil {
		return fmt.Errorf("event sink: %w", err)
	}

	if err := logReceiver(ctx, cfg.LogEndpoint, eg, logger); err != nil {
		return fmt.Errorf("log receiver: %w", err)
	}

	return nil
}

func parsePairs(pairs []string) ([]bindUUIDtoIPv6, error) {
	bindPairs := make([]bindUUIDtoIPv6, 0, len(pairs))

	for _, pair := range pairs {
		uuidStr, addr, found := strings.Cut(pair, "=")
		if !found {
			return nil, fmt.Errorf("invalid UUID=IPv6 pair: %s", pair)
		}

		_, err := uuid.Parse(uuidStr)
		if err != nil {
			return nil, fmt.Errorf("invalid UUID: %s", uuidStr)
		}

		parseAddr, err := netip.ParseAddr(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid IPv6 address: %s", addr)
		}

		bindPairs = append(bindPairs, bindUUIDtoIPv6{
			UUID: uuidStr,
			IPv6: parseAddr,
		})
	}

	return bindPairs, nil
}
