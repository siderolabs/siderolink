// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package main provides the entrypoint for the SideroLink agent.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"go.uber.org/zap"

	"github.com/siderolabs/siderolink/pkg/agent"
)

func main() {
	if err := run(); err != nil {
		println("error :", err.Error())

		os.Exit(1)
	}
}

func run() error {
	var cfg agent.Config

	var predefinedPairs predefinedPairsFlag

	flag.StringVar(&cfg.WireguardEndpoint, "sidero-link-wireguard-endpoint", "172.20.0.1:51821", "advertised Wireguard endpoint")
	flag.StringVar(&cfg.APIEndpoint, "sidero-link-api-endpoint", ":4000", "gRPC API endpoint for the SideroLink")
	flag.StringVar(&cfg.JoinToken, "sidero-link-join-token", "", "join token")
	flag.BoolVar(&cfg.ForceUserspace, "sidero-link-force-userspace", false, "force usage of userspace UDP device for Wireguard")
	flag.StringVar(&cfg.SinkEndpoint, "event-sink-endpoint", ":8080", "gRPC API endpoint for the Event Sink")
	flag.StringVar(&cfg.LogEndpoint, "log-receiver-endpoint", ":4001", "TCP log receiver endpoint")
	flag.Var(&predefinedPairs, "predefined-pairs", "predefined pairs of UUID=IPv6 addrs for the nodes")
	flag.Parse()

	cfg.UUIDIPv6Pairs = predefinedPairs

	logger, err := zap.NewDevelopment()
	if err != nil {
		return fmt.Errorf("error creating logger: %w", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	return agent.Run(ctx, cfg, nil, logger)
}

type predefinedPairsFlag []string

func (p *predefinedPairsFlag) String() string {
	return strings.Join(*p, " ")
}

func (p *predefinedPairsFlag) Set(s string) error {
	*p = append(*p, s)

	return nil
}
