// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"context"
	"net"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"inet.af/netaddr"

	"github.com/talos-systems/siderolink/pkg/logreceiver"
)

var logReceiverFlags struct {
	endpoint string
}

func logHandler(logger *zap.Logger) logreceiver.Handler {
	return func(srcAddress netaddr.IP, msg map[string]interface{}) {
		logger.Info("kernel log message", zap.Stringer("src_address", srcAddress), zap.Any("msg", msg))
	}
}

func logReceiver(ctx context.Context, eg *errgroup.Group, logger *zap.Logger) error {
	lis, err := net.Listen("tcp", logReceiverFlags.endpoint)
	if err != nil {
		return err
	}

	srv, err := logreceiver.NewServer(logger, lis, logHandler(logger))
	if err != nil {
		return err
	}

	eg.Go(func() error {
		return srv.Serve()
	})

	eg.Go(func() error {
		<-ctx.Done()

		srv.Stop()

		return nil
	})

	return nil
}
