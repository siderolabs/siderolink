// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package wireguard

import (
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// PeerSource is the interface of the "database" providing SideroLink peer information.
type PeerSource interface {
	EventCh() <-chan PeerEvent
}

// PeerEvent is the event about peer state change.
//
//nolint:govet
type PeerEvent struct {
	PubKey wgtypes.Key

	Remove   bool
	Endpoint string

	Address netip.Addr

	PersistentKeepAliveInterval *time.Duration

	VirtualAddr netip.Addr
}
