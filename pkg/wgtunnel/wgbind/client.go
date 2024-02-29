// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package wgbind

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sync"

	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/conn"

	"github.com/siderolabs/siderolink/pkg/queue"
)

// NewClientBind creates a new ClientBind.
func NewClientBind(peerQueues *QueuePair, logger *zap.Logger) *ClientBind {
	return &ClientBind{peerQueues: peerQueues, l: logger}
}

// ClientBind implements [conn.Bind] and is used to send and receive packets to and from the server over grpc connection.
// It is used on the "Talos" side.
//
//nolint:govet
type ClientBind struct {
	peerQueues *QueuePair
	l          *zap.Logger

	mx     sync.Mutex
	ctx    context.Context //nolint:containedctx
	cancel context.CancelFunc
}

// Open implements [conn.Bind]. It will use the peerQueues [*QueuePair] to receive packets from the handler.
func (c *ClientBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	defer c.l.Info("opened client")

	c.mx.Lock()
	if c.ctx != nil {
		c.mx.Unlock()

		return nil, 0, conn.ErrBindAlreadyOpen
	}

	c.ctx, c.cancel = context.WithCancel(context.Background())
	ctx := c.ctx
	c.mx.Unlock()

	return []conn.ReceiveFunc{
		func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			p, err := c.peerQueues.FromPeer.Pop(ctx)
			if err != nil {
				c.l.Debug("client bind queue closed")

				return 0, net.ErrClosed
			}

			sizes[0] = copy(packets[0], p.Data)
			eps[0] = &customEndpoint{addr: p.Addr}

			c.l.Debug("client bind got server message", zap.String("src", p.Addr), zap.Int("len", sizes[0]))

			return 1, nil
		},
	}, 65530, nil
}

// Send implements [conn.Bind]. It will use the peerQueues [*QueuePair] to send packets to the handler.
func (c *ClientBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	c.mx.Lock()
	ctx := c.ctx
	c.mx.Unlock()

	for _, buf := range bufs {
		c.l.Debug("client pushing packet 'to peer queue'", zap.String("dst", ep.DstToString()))

		if err := c.peerQueues.ToPeer.Push(ctx, Packet{
			Addr: ep.DstToString(),
			Data: slices.Clone(buf),
		}); err != nil {
			return nil //nolint:nilerr
		}

		c.l.Debug("client pushed packet 'to peer queue'", zap.String("dst", ep.DstToString()))
	}

	return nil
}

// ParseEndpoint implements [conn.Bind].
func (c *ClientBind) ParseEndpoint(endpoint string) (conn.Endpoint, error) {
	defer c.l.Debug("client parsed enpoint", zap.String("endpoint", endpoint))

	return &customEndpoint{addr: endpoint}, nil
}

// BatchSize implements [conn.Bind].
func (c *ClientBind) BatchSize() int { return 1 }

// SetMark implements [conn.Bind]. Unused for "client" side.
func (c *ClientBind) SetMark(uint32) error { return nil }

// Close implements [conn.Bind]. It will close the context to unblock our own ReceiveFunc.
func (c *ClientBind) Close() error {
	c.mx.Lock()
	defer c.mx.Unlock()

	if c.ctx == nil {
		return nil
	}

	defer c.l.Debug("closed client")

	c.cancel()
	c.ctx = nil
	c.cancel = nil

	return nil
}

type customEndpoint struct {
	addr string
}

func (c *customEndpoint) ClearSrc() {}

func (c *customEndpoint) SrcToString() string {
	return ""
}

func (c *customEndpoint) DstToString() string {
	return c.addr
}

func (c *customEndpoint) DstToBytes() []byte {
	return []byte(c.addr)
}

func (c *customEndpoint) DstIP() netip.Addr {
	ap := netip.MustParseAddrPort(c.addr)

	return ap.Addr()
}

func (c *customEndpoint) SrcIP() netip.Addr {
	return netip.Addr{}
}

// NewQueuePair creates a new [QueuePair].
func NewQueuePair(fromPeerMax, toPeerMax int) *QueuePair {
	return &QueuePair{
		FromPeer: queue.New[Packet](fromPeerMax),
		ToPeer:   queue.NewRingQueue[Packet](toPeerMax),
	}
}

// QueuePair is a pair of queues for the client to communicate with the server.
// It is used on "Talos" side.
type QueuePair struct {
	FromPeer queue.Queue[Packet]      // FromPeer essentially is a queue of packets from the server.
	ToPeer   *queue.RingQueue[Packet] // ToPeer essentially is a queue of packets to the server.
}

// Packet is a packet with an address.
type Packet struct {
	Addr string
	Data []byte
}
