// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package wgbind

import (
	"context"
	"sync"

	pb "github.com/siderolabs/siderolink/api/siderolink"
	"github.com/siderolabs/siderolink/pkg/queue"
)

// NewPeerTraffic returns a new [PeerTraffic] with the given maxFromPeers - the number of maxiumum packets from peers
// that we can hold in our queue before blocking [PeerTraffic.PushRecvData].
func NewPeerTraffic(maxFromPeers int) *PeerTraffic {
	return &PeerTraffic{
		FromPeers: queue.New[ReceiveData](maxFromPeers),
		queueMap:  map[string]*queue.RingQueue[[]byte]{},
	}
}

// PeerTraffic is a struct that holds the traffic from peers and the traffic to peers.
// Essentially it's queue for packets to "server" and map of ring-queues for packets to "clients".
// It's used to communicate with the external handler to actually send and receive packets.
// It's used on the "Omni" side.
//
//nolint:govet
type PeerTraffic struct {
	FromPeers queue.Queue[ReceiveData]

	mx       sync.Mutex
	queueMap map[string]*queue.RingQueue[[]byte]
}

// PushRecvData pushes a new ReceiveData to the queue. It will block until the message is pushed or the context is done.
func (p *PeerTraffic) PushRecvData(ctx context.Context, rd ReceiveData) error {
	return p.FromPeers.Push(ctx, rd)
}

// PopRecvData pops a new ReceiveData from the queue. It will block until the message is popped or the context is done.
func (p *PeerTraffic) PopRecvData(ctx context.Context) (ReceiveData, error) {
	return p.FromPeers.Pop(ctx)
}

// GetSendQueue returns the ring queue for the given address. If create is true, it will create a new queue if it doesn't exist.
// It's used to send packets to the "clients".
func (p *PeerTraffic) GetSendQueue(addr string, create bool) (*queue.RingQueue[[]byte], bool) {
	p.mx.Lock()
	defer p.mx.Unlock()

	if q, ok := p.queueMap[addr]; ok {
		return q, true
	}

	if !create {
		return nil, false
	}

	q := queue.NewRingQueue[[]byte](100)

	p.queueMap[addr] = q

	return q, true
}

// RemoveQueue removes the queue for the given address. It's used to remove the queue for the "client" when it's disconnected.
func (p *PeerTraffic) RemoveQueue(addr string) {
	p.mx.Lock()
	defer p.mx.Unlock()

	delete(p.queueMap, addr)
}

// ReceiveData is a struct that holds the address and the packet received from the peer.
type ReceiveData struct {
	Packet *pb.PeerPacket
	Addr   string
}
