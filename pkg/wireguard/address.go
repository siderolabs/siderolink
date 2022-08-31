// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package wireguard

import (
	"net/netip"

	"github.com/talos-systems/talos/pkg/machinery/resources/network"
)

// NetworkPrefix returns IPv6 prefix for the SideroLink.
//
// Server is using the first address in the block.
// Nodes are using random addresses from the /64 space.
func NetworkPrefix(installationID string) netip.Prefix {
	return network.ULAPrefix(installationID, network.ULASideroLink)
}
