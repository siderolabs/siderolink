// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package tun wraps the wg tunnel implementation and adds packet filters.
package tun

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"golang.zx2c4.com/wireguard/tun"
)

// PacketHeader is the decoded representation of the wireguard packet.
type PacketHeader struct {
	SourceAddr      netip.Addr
	DestinationAddr netip.Addr
	FlowLabel       uint32
	PayloadLength   uint16
	Version         uint8
	TrafficClass    uint8
	NextHeader      uint8
	HopLimit        uint8
}

// InputPacketFilter is the function for filtering the packets going through the wireguard tunnel.
type InputPacketFilter func(PacketHeader) bool

// FilterAllExceptIP drops all packets that have the destination different from the ip specified.
func FilterAllExceptIP(ip netip.Addr) InputPacketFilter {
	return func(p PacketHeader) bool {
		return p.DestinationAddr != ip
	}
}

// Device wraps wg tunnel device.
type Device struct {
	tun.Device
	InputPacketFilters []InputPacketFilter
}

// CreateTUN creates a Device with the provided name and MTU.
func CreateTUN(iface string, mtu int, packetFilters ...InputPacketFilter) (*Device, error) {
	tun, err := tun.CreateTUN(iface, mtu)
	if err != nil {
		return nil, fmt.Errorf("error creating tun device: %w", err)
	}

	return &Device{Device: tun, InputPacketFilters: packetFilters}, nil
}

// Write one or more packets to the device (without any additional headers).
// On a successful write it returns the number of packets written. A nonzero
// offset can be used to instruct the Device on where to begin writing from
// each packet contained within the bufs slice.
func (d *Device) Write(bufs [][]byte, offset int) (int, error) {
	if len(d.InputPacketFilters) > 0 {
		result := bufs[:0]

		for _, buf := range bufs {
			packet, err := d.decodePacketHeader(buf[offset:])
			if err != nil {
				continue
			}

			var drop bool

			for _, filter := range d.InputPacketFilters {
				if filter(packet) {
					drop = true

					break
				}
			}

			if !drop {
				result = append(result, buf)
			}
		}

		bufs = result
	}

	return d.Device.Write(bufs, offset)
}

func (*Device) decodePacketHeader(data []byte) (PacketHeader, error) {
	if len(data) < 54 {
		return PacketHeader{}, fmt.Errorf("packet too short to be a valid IPv6 header")
	}

	packetHeader := PacketHeader{}
	packetHeader.Version = data[0] >> 4

	if packetHeader.Version != 6 {
		return packetHeader, fmt.Errorf("invalid packet version")
	}

	var ok bool

	packetHeader.TrafficClass = (data[0]&0x0F)<<4 | (data[1] >> 4)
	packetHeader.FlowLabel = uint32(data[1]&0x0F)<<16 | uint32(data[2])<<8 | uint32(data[3])
	packetHeader.PayloadLength = binary.BigEndian.Uint16(data[4:6])
	packetHeader.NextHeader = data[6]
	packetHeader.HopLimit = data[7]

	packetHeader.SourceAddr, ok = netip.AddrFromSlice(data[8:24])
	if !ok {
		return packetHeader, fmt.Errorf("failed to decode source address")
	}

	packetHeader.DestinationAddr, ok = netip.AddrFromSlice(data[24:40])
	if !ok {
		return packetHeader, fmt.Errorf("failed to decode dst address")
	}

	return packetHeader, nil
}
