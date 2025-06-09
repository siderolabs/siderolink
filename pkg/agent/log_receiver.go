// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/siderolabs/gen/panicsafe"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/siderolabs/siderolink/pkg/logreceiver"
)

func logHandler(logger *zap.Logger) logreceiver.Handler {
	return func(srcAddress netip.Addr, msg map[string]interface{}) {
		logger.Info("kernel log message", zap.Stringer("src_address", srcAddress), zap.Any("msg", msg))
	}
}

func logReceiver(ctx context.Context, endpoint string, eg *errgroup.Group, logger *zap.Logger) error {
	lis, err := net.Listen("tcp", endpoint)
	if err != nil {
		return fmt.Errorf("error listening for TCP log receiver: %w", err)
	}

	srv := logreceiver.NewServer(logger, lis, logHandler(logger))

	stopServer := sync.OnceFunc(srv.Stop)

	eg.Go(panicsafe.RunErrF(func() error {
		defer stopServer()

		serveErr := srv.Serve()

		if errors.Is(serveErr, net.ErrClosed) && ctx.Err() != nil {
			return nil
		}

		return serveErr
	}))

	context.AfterFunc(ctx, stopServer)

	return nil
}
