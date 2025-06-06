// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package tun_test

import (
	"fmt"
	"net/netip"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	wgtun "golang.zx2c4.com/wireguard/tun"

	"github.com/siderolabs/siderolink/pkg/tun"
)

type MockTunDevice struct {
	packets [][]byte
}

func (m *MockTunDevice) File() *os.File {
	return nil
}

func (m *MockTunDevice) Read([][]byte, []int, int) (int, error) {
	return 0, fmt.Errorf("not implemented")
}

func (m *MockTunDevice) Write(bufs [][]byte, _ int) (int, error) {
	m.packets = append(m.packets, bufs...)

	return len(bufs), nil
}

func (m *MockTunDevice) MTU() (int, error) {
	return 0, fmt.Errorf("not implemented")
}

func (m *MockTunDevice) Name() (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (m *MockTunDevice) Events() <-chan wgtun.Event {
	return nil
}

func (m *MockTunDevice) Close() error {
	return nil
}

func (m *MockTunDevice) BatchSize() int {
	return 0
}

func TestDeviceWriteWithPacketFilter(t *testing.T) {
	mockTun := new(MockTunDevice)
	filter := tun.FilterAllExceptIP(netip.MustParseAddr("fdae:41e4:649b:9303::1"))
	device := &tun.Device{Device: mockTun, InputPacketFilters: []tun.InputPacketFilter{filter}}

	packets := [][]byte{
		{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x60, 0x03, 0xB5, 0x9F, 0x00, 0x20, 0x06, 0x40,
			0xFD, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x03,
			0x18, 0x71, 0x65, 0x13, 0x41, 0x3B, 0xA1, 0x3C,
			0xFD, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x03,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			0xC3, 0x50, 0x97, 0xF6, 0x90, 0xE6, 0xE5, 0x5C,
			0x8A, 0xA6, 0xDA, 0x3A, 0x80, 0x10, 0x01, 0xF4,
			0xF3, 0x3A, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0A,
			0x1F, 0x27, 0x64, 0x14, 0x69, 0x39, 0x90, 0x4C,
		},
		{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x60, 0x00, 0x00, 0x00, 0x00, 0x14, 0x3A, 0x40,
			0xFD, 0xAF, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x03,
			0x18, 0x71, 0x65, 0x13, 0x41, 0x3B, 0xA1, 0x3C,
			0xFD, 0xAF, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x03,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			0xC3, 0x50, 0x97, 0xF6, 0x90, 0xE6, 0xE5, 0x5C,
			0x8A, 0xA6, 0xDA, 0x3A, 0x80, 0x10, 0x01, 0xF4,
			0xF3, 0x3A, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0A,
			0x1F, 0x27, 0x64, 0x14, 0x69, 0x39, 0x90, 0x4C,
		},
	}

	_, err := device.Write(packets, 16)

	require.NoError(t, err)
	assert.Equal(t, 1, len(mockTun.packets))
}
