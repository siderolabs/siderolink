// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package wgbind provides a WireGuard conn.Bind implementation that can be used to proxy wireguard packets
// over other connections.
package wgbind

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"

	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/conn"
)

// NewServerBind creates a new ServerBind.
// deflt is the default [conn.Bind] implementation that will be used for non-grpc traffic.
// grpcPrefix is the prefix that will be used to determine if the traffic should be sent over grpc.
// [PeerTraffic] allows for communication with external handler to actually send and receive packets.
func NewServerBind(defaultConn conn.Bind, grpcPrefix netip.Prefix, pt *PeerTraffic, l *zap.Logger) *ServerBind {
	return &ServerBind{
		defaultConn: defaultConn,
		grpcPeers:   pt,
		grpcPrefix:  grpcPrefix,
		l:           l,
	}
}

// ServerBind is a [conn.Bind] implementation that can be used on "omni" side to receive and send packets to Talos
// side over grpc.
//
//nolint:govet
type ServerBind struct {
	defaultConn conn.Bind
	grpcPeers   *PeerTraffic
	grpcPrefix  netip.Prefix
	l           *zap.Logger

	cancel context.CancelFunc // cancel function will unblock ReceiveFuncs when Close is called.
}

// Open implements [conn.Bind]. It will add a new ReceiveFunc that will receive packets from grpcPeers on top of
// the default ReceiveFuncs.
func (b *ServerBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actualPort, err := b.defaultConn.Open(port)
	if err != nil {
		return fns, actualPort, err
	}

	debugLog(b.l, "opened std-net server", "port", actualPort)

	if b.cancel != nil {
		return fns, actualPort, errors.New("already open")
	}

	ctx, cancel := context.WithCancel(context.Background())

	fns = append(wrapWithDebugLogger(b.l, fns), func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		if len(packets) < 1 {
			return 0, fmt.Errorf("no packets to fill: %w", net.ErrClosed)
		}

		data, err := b.grpcPeers.PopRecvData(ctx)
		if err != nil {
			return 0, net.ErrClosed
		}

		sizes[0] = copy(packets[0], data.Packet.Data)
		eps[0] = &customEndpoint{addr: data.Addr}

		return 1, nil
	})

	b.cancel = cancel

	return fns, actualPort, nil
}

// Close implements [conn.Bind]. It will close the default conn.Bind and cancel the context
// to unblock our own ReceiveFuncs.
func (b *ServerBind) Close() error {
	if b.cancel != nil {
		b.cancel()

		b.cancel = nil
	}

	err := b.defaultConn.Close()

	debugLog(b.l, "closed std-net server", "err", err)

	return err
}

// SetMark implements [conn.Bind].
func (b *ServerBind) SetMark(mark uint32) error {
	debugLog(b.l, "setting mark", "mark", mark)

	return b.defaultConn.SetMark(mark)
}

// Send implements [conn.Bind]. It will send the packets over grpc if the destination is in the grpcPrefix.
// Otherwise, it will send the packets over the default conn.Bind.
func (b *ServerBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	if !b.grpcPrefix.Contains(netip.MustParseAddrPort(ep.DstToString()).Addr()) {
		for _, buf := range bufs {
			debugLog(b.l, "sending packet to non-grpc peer", "packet len", len(buf))
		}

		return b.defaultConn.Send(bufs, ep)
	}

	queue, ok := b.grpcPeers.GetSendQueue(ep.DstToString(), false)
	if !ok {
		// No queue for this peer, so we can't send the packet. Just ignore it.
		return nil
	}

	for _, buf := range bufs {
		debugLog(b.l, "sending packet to grpc peer", "packet_len", len(buf))

		// We can pass context.Background() here because queue is a RingQueue, so it will never
		// block on Push for long.
		if err := queue.Push(context.Background(), slices.Clone(buf)); err != nil {
			return nil //nolint:nilerr
		}
	}

	return nil
}

// ParseEndpoint implements [conn.Bind].
func (b *ServerBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	debugLog(b.l, "parsing endpoint", "endpoint", s)

	return b.defaultConn.ParseEndpoint(s)
}

// BatchSize implements [conn.Bind].
func (b *ServerBind) BatchSize() int {
	batchSize := b.defaultConn.BatchSize()

	debugLog(b.l, "getting batch size", "batch_size", batchSize)

	return batchSize
}

const debugOutput = false

func debugLog[T any](l *zap.Logger, msg string, fileName string, field T) {
	if !debugOutput {
		return
	}

	l.Debug(msg, zap.Any(fileName, field))
}

func wrapWithDebugLogger(l *zap.Logger, fns []conn.ReceiveFunc) []conn.ReceiveFunc {
	if !debugOutput {
		return fns
	}

	return wrapWithDebugLoggerSlow(l, fns)
}

func wrapWithDebugLoggerSlow(l *zap.Logger, fns []conn.ReceiveFunc) []conn.ReceiveFunc {
	result := make([]conn.ReceiveFunc, len(fns))

	for i, fn := range fns {
		l.Debug("wrapping with debug logger", zap.Int("i", i))

		result[i] = func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			l.Debug("non GRPC ReceiveFunc start", zap.Int("i", i), zap.Int("len", len(packets)))

			n, err := fn(packets, sizes, eps)
			if err != nil {
				l.Debug("non GRPC ReceiveFunc returned error", zap.Error(err))

				return n, err
			}

			l.Debug("non GRPC ReceiveFunc returned", zap.Int("n", n), zap.Int("i", i))

			for j := range n {
				l.Debug(
					"non GRPC ReceiveFunc packet",
					zap.Int("size", sizes[j]),
					zap.String("local", eps[j].SrcToString()),
					zap.String("remote", eps[j].DstToString()),
				)
			}

			return n, nil
		}
	}

	l.Debug("wrapped with debug logger", zap.Int("len", len(fns)))

	return result
}
