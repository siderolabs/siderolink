// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package wireguard manages user-space Wireguard interface.
package wireguard

import (
	"context"
	"fmt"
	"net"

	"github.com/jsimonetti/rtnetlink/rtnl"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"inet.af/netaddr"
)

const interfaceName = "siderolink"

// Device manages Wireguard link.
type Device struct {
	tun        tun.Device
	address    netaddr.IPPrefix
	privateKey wgtypes.Key
	listenPort uint16
}

// NewDevice creates a new device with settings.
func NewDevice(address netaddr.IPPrefix, privateKey wgtypes.Key, listenPort uint16) (*Device, error) {
	dev := &Device{
		address:    address,
		privateKey: privateKey,
		listenPort: listenPort,
	}

	var err error

	dev.tun, err = tun.CreateTUN(interfaceName, device.DefaultMTU)
	if err != nil {
		return nil, fmt.Errorf("error creating tun device: %w", err)
	}

	return dev, nil
}

// Run the device.
func (dev *Device) Run(ctx context.Context, logger *zap.Logger, peers PeerSource) error {
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("error initializing Wireguard client: %w", err)
	}

	defer client.Close() //nolint:errcheck

	rtnlClient, err := rtnl.Dial(nil)
	if err != nil {
		return fmt.Errorf("error initializing netlink client: %w", err)
	}

	defer rtnlClient.Close() //nolint:errcheck

	wgLogger := &device.Logger{
		Verbosef: logger.Sugar().Debugf,
		Errorf:   logger.Sugar().Errorf,
	}

	uapi, err := UAPIOpen(interfaceName)
	if err != nil {
		return fmt.Errorf("error listenening on uapi socket: %w", err)
	}

	defer uapi.Close() //nolint:errcheck

	device := device.NewDevice(dev.tun, conn.NewDefaultBind(), wgLogger)

	defer device.Close()

	errs := make(chan error)

	go func() {
		for {
			conn, e := uapi.Accept()
			if e != nil {
				errs <- e

				return
			}

			go device.IpcHandle(conn)
		}
	}()

	listenPort := int(dev.listenPort)

	if err = client.ConfigureDevice(interfaceName, wgtypes.Config{
		PrivateKey: &dev.privateKey,
		ListenPort: &listenPort,
	}); err != nil {
		return fmt.Errorf("error configuring Wireguard private key: %w", err)
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return fmt.Errorf("error finding interface: %w", err)
	}

	if err = rtnlClient.AddrAdd(iface, dev.address.IPNet()); err != nil {
		return fmt.Errorf("error setting address: %w", err)
	}

	if err = rtnlClient.LinkUp(iface); err != nil {
		return fmt.Errorf("error bringing link up: %w", err)
	}

	logger.Info("wireguard device set up", zap.String("interface", interfaceName), zap.Stringer("address", dev.address))

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-errs:
			return nil
		case <-device.Wait():
			return nil
		case peerEvent := <-peers.EventCh():
			if err := dev.handlePeerEvent(client, logger, peerEvent); err != nil {
				return err
			}
		}
	}
}

func (dev *Device) checkDuplicateUpdate(client *wgctrl.Client, logger *zap.Logger, peerEvent PeerEvent) (bool, error) {
	oldCfg, err := client.Device(interfaceName)
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

			if prefix, ok := netaddr.FromStdIPNet(&oldPeer.AllowedIPs[0]); ok {
				if prefix.IP() == peerEvent.Address {
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

func (dev *Device) handlePeerEvent(client *wgctrl.Client, logger *zap.Logger, peerEvent PeerEvent) error {
	if !peerEvent.Remove {
		skipEvent, err := dev.checkDuplicateUpdate(client, logger, peerEvent)
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
			*netaddr.IPPrefixFrom(peerEvent.Address, peerEvent.Address.BitLen()).IPNet(),
		}

		logger.Info("updating peer", zap.Stringer("public_key", peerEvent.PubKey), zap.Stringer("address", peerEvent.Address))
	} else {
		logger.Info("removing peer", zap.Stringer("public_key", peerEvent.PubKey))
	}

	if err := client.ConfigureDevice(interfaceName, cfg); err != nil {
		return fmt.Errorf("error configuring Wireguard peers: %w", err)
	}

	return nil
}

// Close the device.
func (dev *Device) Close() error {
	return nil
}
