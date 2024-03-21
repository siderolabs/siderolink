// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package wireguard

import (
	"crypto/rand"
	"crypto/sha256"
	"io"
	"net/netip"
)

// NetworkPrefix returns IPv6 prefix for the SideroLink.
//
// Server is using the first address in the block.
// Nodes are using random addresses from the /64 space.
func NetworkPrefix(installationID string) netip.Prefix {
	return networkPrefix(installationID, 0x3)
}

// VirtualNetworkPrefix returns IPv6 prefix for the SideroLink over GRPC.
// Virtual nodes will use random addresses from the /64 space.
func VirtualNetworkPrefix() netip.Prefix {
	return networkPrefix("", 0x4)
}

func networkPrefix(installationID string, suffix byte) netip.Prefix {
	var prefixData [16]byte

	hash := sha256.Sum256([]byte(installationID))

	// Take the last 16 bytes of the clusterID's hash.
	copy(prefixData[:], hash[sha256.Size-16:])

	// Apply the ULA prefix as per RFC4193
	prefixData[0] = 0xfd

	// Apply the Talos-specific ULA Purpose suffix (SideroLink)
	// We are not importing Talos machinery package here, as Talos imports SideroLink library, and this creates an import cycle.
	prefixData[7] = suffix

	return netip.PrefixFrom(netip.AddrFrom16(prefixData), 64).Masked()
}

// GenerateRandomNodeAddr generates a random node address within the last 8 bytes of the given prefix.
func GenerateRandomNodeAddr(prefix netip.Prefix) (netip.Prefix, error) {
	raw := prefix.Addr().As16()
	salt := make([]byte, 8)

	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return netip.Prefix{}, err
	}

	copy(raw[8:], salt)

	return netip.PrefixFrom(netip.AddrFrom16(raw), prefix.Bits()), nil
}
