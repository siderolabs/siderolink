// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package tun_test

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/siderolabs/siderolink/pkg/tun"
)

// buildIPv6Packet builds a minimal but valid IPv6 packet of the given total length destined to dst,
// prefixed with an all-zero offset region the way wireguard-go hands buffers to the device.
func buildIPv6Packet(offset int, dst netip.Addr, totalLen int) []byte {
	buf := make([]byte, offset+totalLen)
	pkt := buf[offset:]

	pkt[0] = 0x60 // version 6, traffic class 0
	binary.BigEndian.PutUint16(pkt[4:6], uint16(totalLen-40))
	pkt[6] = 59 // next header: no next header (a valid header-only packet)
	pkt[7] = 64 // hop limit

	copy(pkt[24:40], dst.AsSlice())

	return buf
}

// TestDeviceWriteAcceptsMinimalIPv6Packet feeds valid IPv6 packets down to the 40-byte header minimum,
// destined to the allowed address. All must be delivered. Sizes 40 to 53 fail before the header-length
// fix, which rejected anything shorter than 54 bytes.
func TestDeviceWriteAcceptsMinimalIPv6Packet(t *testing.T) {
	allowed := netip.MustParseAddr("fdae:41e4:649b:9303::1")

	for _, size := range []int{40, 48, 53, 54, 60} {
		mockTun := new(MockTunDevice)
		device := &tun.Device{
			Device:             mockTun,
			InputPacketFilters: []tun.InputPacketFilter{tun.FilterAllExceptIP(allowed)},
		}

		const offset = 16

		n, err := device.Write([][]byte{buildIPv6Packet(offset, allowed, size)}, offset)
		require.NoError(t, err)

		assert.Equal(t, 1, n, "a valid %d-byte IPv6 packet to the allowed address must be delivered", size)
		assert.Len(t, mockTun.packets, 1, "a valid %d-byte IPv6 packet to the allowed address must reach the tun", size)
	}
}

// TestDeviceWriteDropsForeignMinimalPacket confirms the filter still drops a valid small packet whose
// destination is not the allowed address, so widening the accepted length does not weaken filtering.
func TestDeviceWriteDropsForeignMinimalPacket(t *testing.T) {
	allowed := netip.MustParseAddr("fdae:41e4:649b:9303::1")
	foreign := netip.MustParseAddr("fdae:41e4:649b:9303::2")

	mockTun := new(MockTunDevice)
	device := &tun.Device{
		Device:             mockTun,
		InputPacketFilters: []tun.InputPacketFilter{tun.FilterAllExceptIP(allowed)},
	}

	const offset = 16

	n, err := device.Write([][]byte{buildIPv6Packet(offset, foreign, 48)}, offset)
	require.NoError(t, err)

	assert.Equal(t, 0, n)
	assert.Empty(t, mockTun.packets)
}

// TestDeviceWriteDropsTooShortPacket locks the low side of the boundary: a packet shorter than the
// 40-byte IPv6 header cannot be decoded and must be dropped on a filtered device.
func TestDeviceWriteDropsTooShortPacket(t *testing.T) {
	allowed := netip.MustParseAddr("fdae:41e4:649b:9303::1")

	mockTun := new(MockTunDevice)
	device := &tun.Device{
		Device:             mockTun,
		InputPacketFilters: []tun.InputPacketFilter{tun.FilterAllExceptIP(allowed)},
	}

	const offset = 16

	buf := make([]byte, offset+39)
	buf[offset] = 0x60 // looks like IPv6, but one byte short of a full header

	n, err := device.Write([][]byte{buf}, offset)
	require.NoError(t, err)

	assert.Equal(t, 0, n)
	assert.Empty(t, mockTun.packets)
}
