// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
)

func main() {
	flag.StringVar(&sideroLinkFlags.wireguardEndpoint, "sidero-link-wireguard-endpoint", "172.20.0.1:51821", "advertised Wireguard endpoint")
	flag.StringVar(&sideroLinkFlags.apiEndpoint, "sidero-link-api-endpoint", ":4000", "gRPC API endpoint for the SideroLink")
	flag.StringVar(&eventSinkFlags.apiEndpoint, "event-sink-endpoint", ":8080", "gRPC API endpoint for the Event Sink")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if err := run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s", err)
	}
}

func run(ctx context.Context) error {
	eg, ctx := errgroup.WithContext(ctx)

	if err := sideroLink(ctx, eg); err != nil {
		return fmt.Errorf("SideroLink: %w", err)
	}

	if err := eventSink(ctx, eg); err != nil {
		return fmt.Errorf("SideroLink: %w", err)
	}

	if err := eg.Wait(); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return err
	}

	return nil
}
