// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package wireguard manages kernel and user-space Wireguard interfaces.
package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
	"go4.org/netipx"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	// PeerDownInterval is the time since last handshake when established peer is considered to be down.
	//
	// WG whitepaper defines a downed peer as being:
	// Handshake Timeout (180s) + Rekey Timeout (5s) + Rekey Attempt Timeout (90s)
	//
	// This interval is applied when the link is already established.
	PeerDownInterval = (180 + 5 + 90) * time.Second

	// LinkMTU is the suggested MTU of the link for Wireguard.
	//
	// Wireguard sets DF (Don't Fragment) bit on all packets, so the MTU of the link
	// should be so that with the overhead of the Wireguard header, the packet
	// is still smaller than the MTU of the link.
	//
	// To be on the safe side, we set the MTU to 1280, which is the minimum MTU
	// for IPv6.
	LinkMTU = 1280

	linkKindWireguard = "wireguard"
)

// Device manages Wireguard link.
type Device struct {
	client *wgctrl.Client
	// ifaceName is the name of the underlying Wireguard interface.
	ifaceName string
	// tun is the underlying userspace wireguard tun device. Its value is nil if native wireguard is used.
	tun        tun.Device
	address    netip.Prefix
	privateKey wgtypes.Key
	clientMu   sync.Mutex
	listenPort uint16
}

// NewDevice creates a new device with settings.
func NewDevice(address netip.Prefix, privateKey wgtypes.Key, listenPort uint16,
	forceUserspace bool, logger *zap.Logger,
) (*Device, error) {
	dev := &Device{
		address:    address,
		privateKey: privateKey,
		listenPort: listenPort,
	}

	var err error

	dev.client, err = wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("error initializing Wireguard client: %w", err)
	}

	if !forceUserspace {
		// attempt to configure a native Wireguard device
		dev.ifaceName, err = createWireguardDevice(interfaceName)
		if err == nil {
			logger.Sugar().Info("using native Wireguard device")

			err = setupIPToInterface(dev)
			if err != nil {
				return nil, err
			}

			return dev, nil
		}

		logger.Sugar().Infof("failed to configure native Wireguard device: %s", err)
	}

	logger.Sugar().Info("attempting to configure tun device (userspace)")

	dev.tun, err = tun.CreateTUN(interfaceName, LinkMTU)
	if err != nil {
		return nil, fmt.Errorf("error creating tun device: %w", err)
	}

	dev.ifaceName, err = dev.tun.Name()
	if err != nil {
		return nil, fmt.Errorf("error getting tun device name: %w", err)
	}

	err = setupIPToInterface(dev)
	if err != nil {
		return nil, err
	}

	return dev, nil
}

func setupIPToInterface(dev *Device) error {
	iface, err := net.InterfaceByName(dev.ifaceName)
	if err != nil {
		return fmt.Errorf("error finding interface: %w", err)
	}

	if err = addIPToInterface(iface, netipx.PrefixIPNet(dev.address)); err != nil {
		return fmt.Errorf("error setting address: %w", err)
	}

	return nil
}

// Run the device.
func (dev *Device) Run(ctx context.Context, logger *zap.Logger, peers PeerSource) error {
	var tunDevice *device.Device

	errs := make(chan error)

	// configure tun device
	if dev.tun != nil {
		wgLogger := &device.Logger{
			Verbosef: logger.Sugar().Debugf,
			Errorf:   logger.Sugar().Errorf,
		}

		uapi, err2 := UAPIOpen(dev.ifaceName)
		if err2 != nil {
			return fmt.Errorf("error listening on uapi socket: %w", err2)
		}

		defer uapi.Close() //nolint:errcheck

		tunDevice = device.NewDevice(dev.tun, conn.NewDefaultBind(), wgLogger)
		defer tunDevice.Close()

		go func() {
			for {
				c, e := uapi.Accept()
				if e != nil {
					errs <- e

					return
				}

				go tunDevice.IpcHandle(c)
			}
		}()
	}

	if err := dev.configurePrivateKey(); err != nil {
		return fmt.Errorf("error configuring Wireguard private key: %w", err)
	}

	iface, err := net.InterfaceByName(dev.ifaceName)
	if err != nil {
		return fmt.Errorf("error finding interface: %w", err)
	}

	if err = linkUp(iface); err != nil {
		return fmt.Errorf("error bringing link up: %w", err)
	}

	logger.Info("wireguard device set up", zap.String("interface", dev.ifaceName), zap.Stringer("address", dev.address))

	var tunDeviceWait chan struct{}

	if tunDevice != nil {
		tunDeviceWait = tunDevice.Wait()
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-errs:
			return nil
		case <-tunDeviceWait:
			return nil
		case peerEvent := <-peers.EventCh():
			if err = dev.handlePeerEvent(logger, peerEvent); err != nil {
				return err
			}
		}
	}
}

// Peers returns underlying peer states from the underlying wireguard device.
func (dev *Device) Peers() ([]wgtypes.Peer, error) {
	dev.clientMu.Lock()
	defer dev.clientMu.Unlock()

	wgDevice, err := dev.client.Device(dev.ifaceName)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("error fetching wireguard link status: %w", err)
	}

	if wgDevice == nil {
		return []wgtypes.Peer{}, nil
	}

	return wgDevice.Peers, nil
}

func (dev *Device) configurePrivateKey() error {
	dev.clientMu.Lock()
	defer dev.clientMu.Unlock()

	listenPort := int(dev.listenPort)

	return dev.client.ConfigureDevice(dev.ifaceName, wgtypes.Config{
		PrivateKey: &dev.privateKey,
		ListenPort: &listenPort,
	})
}

func (dev *Device) checkDuplicateUpdate(client *wgctrl.Client, logger *zap.Logger, peerEvent PeerEvent) (bool, error) {
	oldCfg, err := client.Device(dev.ifaceName)
	if err != nil {
		return false, fmt.Errorf("error retrieving Wireguard configuration: %w", err)
	}

	// check if this update can be skipped
	pubKey := peerEvent.PubKey.String()

	for _, oldPeer := range oldCfg.Peers {
		if oldPeer.PublicKey.String() == pubKey {
			if len(oldPeer.AllowedIPs) != 1 {
				break
			}

			if prefix, ok := netipx.FromStdIPNet(&oldPeer.AllowedIPs[0]); ok {
				if prefix.Addr() == peerEvent.Address {
					// skip the update
					logger.Info("skipping peer update", zap.String("public_key", pubKey))

					return true, nil
				}
			}

			break
		}
	}

	return false, nil
}

func (dev *Device) handlePeerEvent(logger *zap.Logger, peerEvent PeerEvent) error {
	dev.clientMu.Lock()
	defer dev.clientMu.Unlock()

	if !peerEvent.Remove {
		skipEvent, err := dev.checkDuplicateUpdate(dev.client, logger, peerEvent)
		if err != nil {
			return err
		}

		if skipEvent {
			return nil
		}
	}

	cfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: peerEvent.PubKey,
				Remove:    peerEvent.Remove,
			},
		},
	}

	if !peerEvent.Remove {
		cfg.Peers[0].ReplaceAllowedIPs = true
		cfg.Peers[0].AllowedIPs = []net.IPNet{
			*netipx.PrefixIPNet(netip.PrefixFrom(peerEvent.Address, peerEvent.Address.BitLen())),
		}

		if peerEvent.Endpoint != "" {
			ip, err := netip.ParseAddrPort(peerEvent.Endpoint)
			if err != nil {
				return fmt.Errorf("failed to parse last endpoint: %w", err)
			}

			cfg.Peers[0].Endpoint = asUDP(ip)
		}

		logger.Info("updating peer", zap.Stringer("public_key", peerEvent.PubKey), zap.Stringer("address", peerEvent.Address))
	} else {
		logger.Info("removing peer", zap.Stringer("public_key", peerEvent.PubKey))
	}

	if err := dev.client.ConfigureDevice(dev.ifaceName, cfg); err != nil {
		return fmt.Errorf("error configuring Wireguard peers: %w", err)
	}

	return nil
}

// Close the device.
func (dev *Device) Close() error {
	if dev.tun != nil {
		if err := dev.tun.Close(); err != nil {
			return err
		}
	} else {
		if err := deleteWireguardDevice(dev.ifaceName); err != nil {
			return err
		}
	}

	if err := dev.client.Close(); err != nil {
		return err
	}

	return nil
}

func asUDP(addr netip.AddrPort) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   addr.Addr().AsSlice(),
		Port: int(addr.Port()),
		Zone: addr.Addr().Zone(),
	}
}
