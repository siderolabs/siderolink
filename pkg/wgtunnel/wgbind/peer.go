// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package wgbind

import (
	"context"
	"net/netip"
	"sync"

	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	pb "github.com/siderolabs/siderolink/api/siderolink"
	"github.com/siderolabs/siderolink/pkg/queue"
)

// sendQueueCapacity is the number of packets that can be staged for a single peer before the oldest
// ones are dropped.
const sendQueueCapacity = 100

// NewPeerTraffic returns a new [PeerTraffic] with the given maxFromPeers - the number of maxiumum packets from peers
// that we can hold in our queue before blocking [PeerTraffic.PushRecvData].
func NewPeerTraffic(maxFromPeers int, logger *zap.Logger) *PeerTraffic {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &PeerTraffic{
		fromPeers: queue.New[recvData](maxFromPeers),
		logger:    logger,
		byKey:     map[wgtypes.Key]*peerSession{},
		byAddr:    map[netip.AddrPort]*peerSession{},
	}
}

// PeerTraffic is a struct that holds the traffic from peers and the traffic to peers.
// Essentially it's queue for packets to "server" and map of ring-queues for packets to "clients".
// It's used to communicate with the external handler to actually send and receive packets.
// It's used on the "Omni" side.
//
// Sessions are keyed by the peer's public key, which is the peer's only stable identity: its tunnel
// address is reassigned every time it re-provisions. The address is kept as a secondary index, because
// that is all WireGuard hands back on the send path.
//
//nolint:govet
type PeerTraffic struct {
	fromPeers queue.Queue[recvData]
	logger    *zap.Logger

	mx     sync.Mutex
	byKey  map[wgtypes.Key]*peerSession
	byAddr map[netip.AddrPort]*peerSession
}

// peerSession is a live tunnel session for a single peer. It survives the peer reconnecting or moving
// to another tunnel address, so packets already staged for the peer are not lost.
//
// Its fields are guarded by [PeerTraffic.mx].
type peerSession struct {
	queue *queue.RingQueue[[]byte]
	addr  netip.AddrPort
	key   wgtypes.Key
}

// OpenSession opens (or re-opens) the session of the peer identified by pubKey, reachable at addr, and
// returns the queue of the packets to be sent to the peer.
//
// Both mappings are kept 1:1: the peer's previous address stops resolving, and an address claimed by
// another peer is taken away from it. That other peer's key is returned, so the caller can retire
// whatever else it holds on that peer's behalf. The send queue is reused when the peer already had a
// session, so a reconnecting peer keeps the packets staged for it.
func (p *PeerTraffic) OpenSession(pubKey wgtypes.Key, addr netip.AddrPort) (sendQueue *queue.RingQueue[[]byte], displaced wgtypes.Key, hasDisplaced bool) {
	p.mx.Lock()
	defer p.mx.Unlock()

	if prev, ok := p.byAddr[addr]; ok && prev.key != pubKey {
		delete(p.byKey, prev.key)

		displaced, hasDisplaced = prev.key, true
	}

	session, ok := p.byKey[pubKey]
	if !ok {
		session = &peerSession{
			key:   pubKey,
			queue: queue.NewRingQueue[[]byte](sendQueueCapacity),
		}

		p.byKey[pubKey] = session
	} else {
		delete(p.byAddr, session.addr)
	}

	session.addr = addr
	p.byAddr[addr] = session

	return session.queue, displaced, hasDisplaced
}

// CloseSession closes the session of the peer identified by pubKey.
func (p *PeerTraffic) CloseSession(pubKey wgtypes.Key) {
	p.mx.Lock()
	defer p.mx.Unlock()

	session, ok := p.byKey[pubKey]
	if !ok {
		return
	}

	delete(p.byKey, pubKey)
	delete(p.byAddr, session.addr)
}

// PushRecvData pushes a packet received from the peer identified by pubKey to the queue. It will block
// until the packet is pushed or the context is done.
func (p *PeerTraffic) PushRecvData(ctx context.Context, pubKey wgtypes.Key, packet *pb.PeerPacket) error {
	return p.fromPeers.Push(ctx, recvData{pubKey: pubKey, packet: packet})
}

// PopRecvData pops a packet received from a peer, tagged with the address that peer is reachable at
// right now. It will block until a packet is popped or the context is done.
func (p *PeerTraffic) PopRecvData(ctx context.Context) (ReceiveData, error) {
	for {
		data, err := p.fromPeers.Pop(ctx)
		if err != nil {
			return ReceiveData{}, err
		}

		// The address is resolved here, and not when the packet was received, because the peer may have
		// moved to another tunnel address while this packet sat in the queue (or in flight over gRPC).
		// WireGuard adopts the address of every packet it accepts as the peer's endpoint, so tagging a
		// packet with an address that is no longer routable would silently break the send path.
		addr, ok := p.addrFor(data.pubKey)
		if !ok {
			// The peer has no session anymore, so there is nothing left to receive on its behalf.
			p.logger.Debug("dropping packet from a peer without a session",
				zap.Stringer("public_key", data.pubKey), zap.Int("len", len(data.packet.GetData())))

			continue
		}

		return ReceiveData{Packet: data.packet, Addr: addr}, nil
	}
}

// GetSendQueue returns the send queue of the peer currently reachable at addr.
// It's used to send packets to the "clients".
func (p *PeerTraffic) GetSendQueue(addr netip.AddrPort) (*queue.RingQueue[[]byte], bool) {
	p.mx.Lock()
	defer p.mx.Unlock()

	session, ok := p.byAddr[addr]
	if !ok {
		return nil, false
	}

	return session.queue, true
}

func (p *PeerTraffic) addrFor(pubKey wgtypes.Key) (netip.AddrPort, bool) {
	p.mx.Lock()
	defer p.mx.Unlock()

	session, ok := p.byKey[pubKey]
	if !ok {
		return netip.AddrPort{}, false
	}

	return session.addr, true
}

// recvData is a packet as it sits in the queue: tagged with the peer's identity, never with its
// address, which is only resolved on the way out.
type recvData struct {
	packet *pb.PeerPacket
	pubKey wgtypes.Key
}

// ReceiveData is a struct that holds the address and the packet received from the peer.
type ReceiveData struct {
	Packet *pb.PeerPacket
	Addr   netip.AddrPort
}
