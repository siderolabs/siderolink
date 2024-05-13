// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package wireguard_test

import (
	"bytes"
	"encoding/hex"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/siderolabs/gen/ensure"
	"github.com/siderolabs/gen/xtesting/check"
	"github.com/siderolabs/go-pointer"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	"go4.org/netipx"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/siderolabs/siderolink/pkg/wireguard"
)

func TestPrepareDeviceConfig(t *testing.T) {
	//nolint:govet
	tests := map[string]struct {
		peerEvents   []wireguard.PeerEvent
		oldCfg       *wgtypes.Device
		userHandler  wireguard.PeerHandler
		expectedCfgs []wgtypes.PeerConfig
		check        check.Check
	}{
		"empty": {
			peerEvents: nil,
			oldCfg: &wgtypes.Device{
				Name: "if9",
				Type: wgtypes.Userspace,
				Peers: []wgtypes.Peer{
					{
						PublicKey:                   keys[0].PublicKey(),
						PersistentKeepaliveInterval: persistentKeepaliveInterval,
						AllowedIPs: []net.IPNet{
							allowedIps[0],
						},
					},
				},
			},
			expectedCfgs: nil,
			check:        check.NoError(),
		},
		"single": {
			peerEvents: []wireguard.PeerEvent{
				{
					PubKey:                      keys[0].PublicKey(),
					Endpoint:                    endpoints[0],
					Address:                     addresses1[0],
					PersistentKeepAliveInterval: pointer.To(persistentKeepaliveInterval),
				},
			},
			oldCfg: &wgtypes.Device{
				Name:  "if9",
				Type:  wgtypes.Userspace,
				Peers: []wgtypes.Peer{},
			},
			expectedCfgs: []wgtypes.PeerConfig{
				{
					PublicKey:                   keys[0].PublicKey(),
					Endpoint:                    wireguard.AsUDP(netip.MustParseAddrPort(endpoints[0])),
					PersistentKeepaliveInterval: pointer.To(persistentKeepaliveInterval),
					ReplaceAllowedIPs:           true,
					AllowedIPs: []net.IPNet{
						*netipx.PrefixIPNet(netip.PrefixFrom(addresses1[0], addresses1[0].BitLen())),
					},
				},
			},
			check: check.NoError(),
		},
		"deduplicate": {
			peerEvents: []wireguard.PeerEvent{
				{
					PubKey:                      keys[0].PublicKey(),
					Endpoint:                    endpoints[0],
					Address:                     addresses1[0],
					PersistentKeepAliveInterval: pointer.To(persistentKeepaliveInterval),
				},
				{
					PubKey:                      keys[0].PublicKey(),
					Endpoint:                    endpoints[1],
					Address:                     addresses1[1],
					PersistentKeepAliveInterval: pointer.To(persistentKeepaliveInterval),
				},
			},
			oldCfg: &wgtypes.Device{
				Name:  "if9",
				Type:  wgtypes.Userspace,
				Peers: []wgtypes.Peer{},
			},
			expectedCfgs: []wgtypes.PeerConfig{
				{
					PublicKey:                   keys[0].PublicKey(),
					Endpoint:                    wireguard.AsUDP(netip.MustParseAddrPort(endpoints[1])),
					PersistentKeepaliveInterval: pointer.To(persistentKeepaliveInterval),
					ReplaceAllowedIPs:           true,
					AllowedIPs: []net.IPNet{
						*netipx.PrefixIPNet(netip.PrefixFrom(addresses1[1], addresses1[1].BitLen())),
					},
				},
			},
			check: check.NoError(),
		},
		"deduplicate and remove": {
			peerEvents: []wireguard.PeerEvent{
				{
					PubKey:                      keys[0].PublicKey(),
					Endpoint:                    endpoints[0],
					Address:                     addresses1[0],
					PersistentKeepAliveInterval: pointer.To(persistentKeepaliveInterval),
				},
				{
					PubKey:                      keys[0].PublicKey(),
					Endpoint:                    endpoints[1],
					Address:                     addresses1[1],
					PersistentKeepAliveInterval: pointer.To(persistentKeepaliveInterval),
				},
				{
					PubKey:                      keys[0].PublicKey(),
					Remove:                      true,
					Endpoint:                    endpoints[1],
					Address:                     addresses1[1],
					PersistentKeepAliveInterval: pointer.To(persistentKeepaliveInterval),
				},
			},
			oldCfg: &wgtypes.Device{
				Name:  "if9",
				Type:  wgtypes.Userspace,
				Peers: []wgtypes.Peer{},
			},
			expectedCfgs: []wgtypes.PeerConfig{
				{
					PublicKey:                   keys[0].PublicKey(),
					Remove:                      true,
					Endpoint:                    nil,
					PersistentKeepaliveInterval: nil,
					ReplaceAllowedIPs:           false,
					AllowedIPs:                  nil,
				},
			},
			check: check.NoError(),
		},
		"deduplicate and not update": {
			peerEvents: []wireguard.PeerEvent{
				{
					PubKey:                      keys[0].PublicKey(),
					Endpoint:                    endpoints[0],
					Address:                     addresses1[0],
					PersistentKeepAliveInterval: pointer.To(persistentKeepaliveInterval),
				},
				{
					PubKey:                      keys[0].PublicKey(),
					Endpoint:                    endpoints[1],
					Address:                     addresses1[1],
					PersistentKeepAliveInterval: pointer.To(persistentKeepaliveInterval),
				},
			},
			oldCfg: &wgtypes.Device{
				Name: "if9",
				Type: wgtypes.Userspace,
				Peers: []wgtypes.Peer{
					{
						PublicKey:                   keys[0].PublicKey(),
						Endpoint:                    wireguard.AsUDP(netip.MustParseAddrPort(endpoints[1])),
						PersistentKeepaliveInterval: persistentKeepaliveInterval,
						AllowedIPs: []net.IPNet{
							*netipx.PrefixIPNet(netip.PrefixFrom(addresses1[1], addresses1[1].BitLen())),
						},
					},
				},
			},
			expectedCfgs: nil,
			check:        check.NoError(),
		},
		"deduplicate and not update with dummy handler": {
			peerEvents: []wireguard.PeerEvent{
				{
					PubKey:                      keys[0].PublicKey(),
					Endpoint:                    endpoints[0],
					Address:                     addresses1[0],
					PersistentKeepAliveInterval: pointer.To(persistentKeepaliveInterval),
				},
				{
					PubKey:                      keys[0].PublicKey(),
					Endpoint:                    endpoints[1],
					Address:                     addresses1[1],
					PersistentKeepAliveInterval: pointer.To(persistentKeepaliveInterval),
				},
			},
			oldCfg: &wgtypes.Device{
				Name: "if9",
				Type: wgtypes.Userspace,
				Peers: []wgtypes.Peer{
					{
						PublicKey:                   keys[0].PublicKey(),
						Endpoint:                    wireguard.AsUDP(netip.MustParseAddrPort(endpoints[1])),
						PersistentKeepaliveInterval: persistentKeepaliveInterval,
						AllowedIPs: []net.IPNet{
							*netipx.PrefixIPNet(netip.PrefixFrom(addresses1[1], addresses1[1].BitLen())),
						},
					},
				},
			},
			userHandler:  &dummyHandler{},
			expectedCfgs: nil,
			check:        check.NoError(),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			logger := zaptest.NewLogger(t)

			cfgs, err := wireguard.PrepareDeviceConfig(test.peerEvents, test.oldCfg, test.userHandler, logger)
			test.check(t, err)

			require.Equal(t, test.expectedCfgs, cfgs)
		})
	}
}

const (
	persistentKeepaliveInterval = 5 * time.Second
)

var (
	keys       = generate(15, func(i int) wgtypes.Key { return wgtypes.Key(ensure.Value(hex.DecodeString(hexPrivateKeys[i]))) })
	allowedIps = generate(15, func(i int) net.IPNet {
		return *netipx.AddrIPNet(ensure.Value(netip.ParseAddr("192.168." + strconv.Itoa(i+1) + ".1")))
	})
	endpoints  = generate(15, func(i int) string { return "10.168." + strconv.Itoa(i+1) + ".1:51820" })
	addresses1 = generate(15, func(i int) netip.Addr { return ensure.Value(netip.ParseAddr("192.168.1." + strconv.Itoa(i+1))) })
)

func generate[T any](num int, provider func(int) T) []T {
	result := make([]T, 0, num)

	for i := range num {
		result = append(result, provider(i))
	}

	return result
}

var hexPrivateKeys = []string{
	"58006ea952a22a4eaf41675a156c6c4d0689a6731d25081711be8b3c33b8304e",
	"f8d04ba23f54353d1673994ba55e30c6c458a4e294924a1710638554186a4e41",
	"00ff3ecc74a800e1f8f16e72eefd1a449f3e45018868c566ef780d9beaded979",
	"88b74cd82e774788b9c1cf70e57de8c2cba14d0f60b563b103d56c955d6beb5b",
	"a89ce8cd67d1ad8c02cb0f732021170b83c0b098c17b7d86d40237a353112545",
	"684c0b05eea03f9a647b56264f83811cc5075e286b59d76bd0854d59b2b44e4e",
	"28188e8f1152ce867ddeb73cb6352727075939e5b951d33b1be98dd89698b542",
	"0848f67321bd99d6cfa63469969c26c77a094c6e92d20d7a4e9b66de7aa0ae47",
	"088a311588bbca3431af5080d5986c8d7612c67eab1850fc40acd06ae485cd45",
	"b8fcf035b664edb1726820972e65f4db22bee6816d649db0ebb6f112497e3077",
	"306715b408c2892b2fe51713876082b19f84070360a1cca9e01f6983e3e1c541",
	"2816fa691944147c241afd8da013350ad4d30f26d3c0d81fa43f248c733f016c",
	"38d4113e86dadd0d21dabf62c042f72ddf48ce92bff79d4dfde482f4b2ea8c60",
	"6813bb3c74db3a2358dd7ebf7723c31d238331482818a522b5a67e3b998aea6d",
	"000b4b43005f6daf5a39779ae40e0b9fbb875414bd7e48d49505e988c53cd56e",
}

//nolint:unused
func _TestGenPrivateKeys(t *testing.T) {
	result := make([]wgtypes.Key, 0, 15)

	for range 15 {
		k, err := wgtypes.GeneratePrivateKey()
		require.NoError(t, err)

		result = append(result, k)
	}

	slices.SortStableFunc(result, func(a, b wgtypes.Key) int {
		publicKey := a.PublicKey()
		publicKey2 := b.PublicKey()

		return bytes.Compare(publicKey[:], publicKey2[:])
	})

	for _, k := range result {
		println(hex.EncodeToString(k[:]))
	}

	println()

	for _, k := range result {
		k = k.PublicKey()
		println(hex.EncodeToString(k[:]))
	}
}

type dummyHandler struct{}

func (d *dummyHandler) HandlePeerAdded(wireguard.PeerEvent) error { return nil }

func (d *dummyHandler) HandlePeerRemoved(wgtypes.Key) error { return nil }
