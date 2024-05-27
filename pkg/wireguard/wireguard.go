// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package wireguard manages kernel and user-space Wireguard interfaces.
package wireguard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/siderolabs/go-pointer"
	"go.uber.org/multierr"
	"go.uber.org/zap"
	"go4.org/netipx"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/siderolabs/siderolink/pkg/iter"
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

	// RecommendedPersistentKeepAliveInterval is the recommended interval for persistent keepalive.
	RecommendedPersistentKeepAliveInterval = 25 * time.Second

	linkKindWireguard = "wireguard"
)

// Device manages Wireguard link.
//
//nolint:govet
type Device struct {
	dc DeviceConfig

	// ifaceName is the name of the underlying Wireguard interface.
	ifaceName string
	// tun is the underlying userspace wireguard tun device. Its value is nil if native wireguard is used.
	tun tun.Device

	clientMu sync.Mutex
	client   *wgctrl.Client
}

// DeviceConfig is the configuration for the wireguard device.
type DeviceConfig struct {
	// Bind is the bind configuration for the wireguard device. If nil the default bind is used.
	Bind conn.Bind
	// PeerHandler is the optional handler for peer events.
	PeerHandler PeerHandler
	// Logger is the logger to use.
	Logger *zap.Logger
	// ServerPrefix is the prefix to bind to the wireguard device.
	ServerPrefix netip.Prefix
	// PrivateKey is the server private key.
	PrivateKey wgtypes.Key
	// AutoPeerRemoveInterval is the checks interval to remove downed peers. If zero, it's disabled.
	AutoPeerRemoveInterval time.Duration
	// ListenPort is the port to listen on. If zero, a random port is used.
	ListenPort uint16
	// ForceUserspace forces the use of userspace wireguard implementation. If Bind is set this field is always true.
	ForceUserspace bool
}

// PeerHandler is an interface for handling peer events.
type PeerHandler interface {
	HandlePeerAdded(event PeerEvent) error
	HandlePeerRemoved(pubKey wgtypes.Key) error
}

// NewDevice creates a new device with settings.
func NewDevice(config DeviceConfig) (*Device, error) {
	config.ForceUserspace = config.ForceUserspace || config.Bind != nil

	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("error initializing Wireguard client: %w", err)
	}

	if !config.ForceUserspace {
		// attempt to configure a native Wireguard device
		var ifaceName string

		ifaceName, err = createWireguardDevice(InterfaceName)
		if err == nil {
			config.Logger.Sugar().Info("using native Wireguard device")

			_, err = SetupIPToInterface(config.ServerPrefix, ifaceName)
			if err != nil {
				return nil, err
			}

			return &Device{
				dc:        config,
				ifaceName: ifaceName,
				client:    client,
			}, nil
		}

		config.Logger.Sugar().Infof("failed to configure native Wireguard device: %s", err)
	}

	config.Logger.Info("attempting to configure tun device (userspace)", zap.Stringer("serverPrefix", config.ServerPrefix))

	createdTun, err := tun.CreateTUN(InterfaceName, LinkMTU)
	if err != nil {
		return nil, fmt.Errorf("error creating tun device: %w", err)
	}

	ifaceName, err := createdTun.Name()
	if err != nil {
		return nil, fmt.Errorf("error getting tun device name: %w", err)
	}

	_, err = SetupIPToInterface(config.ServerPrefix, ifaceName)
	if err != nil {
		return nil, err
	}

	return &Device{
		dc:        config,
		ifaceName: ifaceName,
		tun:       createdTun,
		client:    client,
	}, nil
}

// SetupIPToInterface sets up the IP address to the interface.
func SetupIPToInterface(address netip.Prefix, ifaceName string) (func() error, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("error finding interface: %w", err)
	}

	if err = addIPToInterface(iface, netipx.PrefixIPNet(address)); err != nil {
		return nil, fmt.Errorf("error setting address: %w", err)
	}

	return func() error {
		return removeIPFromInterface(iface, address)
	}, nil
}

// Run the device.
func (dev *Device) Run(ctx context.Context, logger *zap.Logger, peers PeerSource) error {
	var tunDevice *device.Device

	errs := make(chan error, 1)

	// configure tun device
	if dev.tun != nil {
		var wg sync.WaitGroup

		defer func() {
			// Both [ipc.UAPIOpen] and [device.Device] do not wait for their goroutines to finish properly,
			// so this is our best effort attempt to wait for them to finish.
			time.Sleep(100 * time.Millisecond)

			wg.Wait()
		}()

		bnd := dev.dc.Bind
		if bnd == nil {
			bnd = conn.NewDefaultBind()
		}

		tunDevice = device.NewDevice(dev.tun, bnd, DeviceLogger(logger))
		defer tunDevice.Close()

		// link spec resource for wireguard created by talos
		uapi, err := UAPIOpen(dev.ifaceName)
		if err != nil {
			return fmt.Errorf("error listening on uapi socket: %w", err)
		}

		defer func() {
			if err := uapi.Close(); err != nil {
				fmt.Println("error closing uapi socket: %w", err)
			}
		}()

		wg.Add(1)

		go func() {
			defer wg.Done()

			for {
				c, e := uapi.Accept()
				if e != nil {
					errs <- e

					return
				}

				wg.Add(1)

				go func() {
					defer wg.Done()

					tunDevice.IpcHandle(c)
				}()
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

	if err = LinkUp(iface); err != nil {
		return fmt.Errorf("error bringing link up: %w", err)
	}

	logger.Info("wireguard device set up", zap.String("interface", dev.ifaceName), zap.Stringer("server_prefix", dev.dc.ServerPrefix))

	var tunDeviceWait chan struct{}

	if tunDevice != nil {
		tunDeviceWait = tunDevice.Wait()
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	eventsCh, releaseSlice := runPeersDrainer(ctx, peers)

	handlePeerEvent := func(events []PeerEvent) error {
		defer releaseSlice(events)

		return dev.handlePeerEvent(events, logger)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-errs:
			return nil
		case <-tunDeviceWait:
			return nil
		case <-timeAfter(dev.dc.AutoPeerRemoveInterval):
			if err = dev.cleanupPeers(logger); err != nil {
				return err
			}
		case events := <-eventsCh:
			if err = handlePeerEvent(events); err != nil {
				return err
			}
		}
	}
}

// DeviceLogger returns a [device.Logger] that logs to the given [zap.Logger].
func DeviceLogger(logger *zap.Logger) *device.Logger {
	verboseFn := func(string, ...any) {}

	if logger.Level() == zap.DebugLevel {
		verboseFn = logger.Sugar().Debugf
	}

	return &device.Logger{
		Verbosef: verboseFn,
		Errorf:   logger.Sugar().Warnf,
	}
}

func timeAfter(interval time.Duration) <-chan time.Time {
	if interval == 0 {
		return nil
	}

	return time.After(interval)
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

	return dev.client.ConfigureDevice(dev.ifaceName, wgtypes.Config{
		PrivateKey: &dev.dc.PrivateKey,
		ListenPort: pointer.To(int(dev.dc.ListenPort)),
	})
}

func (dev *Device) handlePeerEvent(peerEvents []PeerEvent, logger *zap.Logger) error {
	dev.clientMu.Lock()
	defer dev.clientMu.Unlock()

	oldCfg, err := dev.client.Device(dev.ifaceName)
	if err != nil {
		return err
	}

	cfgs, err := PrepareDeviceConfig(peerEvents, oldCfg, dev.dc.PeerHandler, logger)

	if len(cfgs) == 0 {
		return err
	}

	// err may be non-nil if there was an error but cfgs are still valid if not empty
	if confErr := dev.client.ConfigureDevice(dev.ifaceName, wgtypes.Config{Peers: cfgs}); confErr != nil {
		err = multierr.Append(err, fmt.Errorf("error configuring Wireguard peers: %w", confErr))
	}

	return err
}

func (dev *Device) cleanupPeers(logger *zap.Logger) error {
	dev.clientMu.Lock()
	defer dev.clientMu.Unlock()

	peersToRemove, err := dev.getPeersToRemove()
	if err != nil {
		return fmt.Errorf("error fetching downed peers: %w", err)
	}

	if len(peersToRemove) == 0 {
		return nil
	}

	if handler := dev.dc.PeerHandler; handler != nil {
		for _, peer := range peersToRemove {
			if err := handler.HandlePeerRemoved(peer.PublicKey); err != nil {
				return fmt.Errorf("error handling peer removed event: %w", err)
			}
		}
	}

	for _, peer := range peersToRemove {
		logger.Info("removing downed peer", zap.Stringer("public_key", peer.PublicKey))
	}

	if err := dev.client.ConfigureDevice(dev.ifaceName, wgtypes.Config{Peers: peersToRemove}); err != nil {
		return fmt.Errorf("error removing downed peers: %w", err)
	}

	return nil
}

func (dev *Device) getPeersToRemove() ([]wgtypes.PeerConfig, error) {
	w, err := dev.client.Device(dev.ifaceName)
	if err != nil {
		return nil, fmt.Errorf("error fetching wireguard link status: %w", err)
	}

	result := make([]wgtypes.PeerConfig, 0, len(w.Peers))

	for _, peer := range w.Peers {
		if peer.LastHandshakeTime.IsZero() || time.Since(peer.LastHandshakeTime) < PeerDownInterval {
			continue
		}

		result = append(result, wgtypes.PeerConfig{
			PublicKey: peer.PublicKey,
			Remove:    true,
		})
	}

	return result, nil
}

// Close the device.
func (dev *Device) Close() (err error) {
	defer func() {
		closeErr := dev.client.Close()

		if err == nil {
			err = closeErr
		} else {
			err = fmt.Errorf("%w; client close err: %w", err, closeErr)
		}
	}()

	if dev.tun != nil {
		err = dev.tun.Close()
	} else {
		err = deleteWireguardDevice(dev.ifaceName)
	}

	return nil
}

// AsUDP converts netip.AddrPort to net.UDPAddr.
func AsUDP(addr netip.AddrPort) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   addr.Addr().AsSlice(),
		Port: int(addr.Port()),
		Zone: addr.Addr().Zone(),
	}
}

func runPeersDrainer(ctx context.Context, peers PeerSource) (chan []PeerEvent, func([]PeerEvent)) {
	pool := sync.Pool{
		New: func() any { return make([]PeerEvent, 0, 100) },
	}

	resultCh := make(chan []PeerEvent)

	go func() {
		var (
			slc = pool.Get().([]PeerEvent) //nolint:errcheck,forcetypeassert
			ch  chan []PeerEvent
		)

		for {
			select {
			case <-ctx.Done():
				return
			case peerEvent := <-peers.EventCh():
				slc = append(slc, peerEvent)
				// allow sending only if we have events in our slice
				ch = resultCh
			case ch <- slc:
				slc = pool.Get().([]PeerEvent) //nolint:errcheck,forcetypeassert
				// disallow sending until we get an event
				ch = nil
			}
		}
	}()

	return resultCh, func(slc []PeerEvent) {
		clear(slc)
		pool.Put(slc[:0]) //nolint:staticcheck
	}
}

// PrepareDeviceConfig takes a list of peer events and prepares a list of peer configurations comparing them with the old configuration.
func PrepareDeviceConfig(peerEvents []PeerEvent, oldCfg *wgtypes.Device, userHandler PeerHandler, logger *zap.Logger) ([]wgtypes.PeerConfig, error) {
	if oldCfg == nil {
		panic("oldCfg is nil")
	}

	slices.SortStableFunc(peerEvents, func(a, b PeerEvent) int { return bytes.Compare(a.PubKey[:], b.PubKey[:]) })

	it := iter.Deduplicate(peerEvents, func(a, b PeerEvent) bool { return a.PubKey == b.PubKey })

	var err error

	if userHandler != nil {
		it = iter.Filter(it, func(event PeerEvent) bool {
			var handleErr error

			if event.Remove {
				handleErr = userHandler.HandlePeerRemoved(event.PubKey)
			} else {
				handleErr = userHandler.HandlePeerAdded(event)
			}

			if handleErr != nil {
				err = multierr.Append(err, fmt.Errorf("peer handler failed on peer event %w", handleErr))

				return false
			}

			return true
		})
	}

	peers := make([]wgtypes.PeerConfig, 0, len(peerEvents))
	it = checkDuplicateUpdates(it, oldCfg, logger)

	it(func(peerEvent PeerEvent) bool {
		peerCfg := wgtypes.PeerConfig{
			PublicKey: peerEvent.PubKey,
			Remove:    peerEvent.Remove,
		}

		if !peerEvent.Remove {
			peerCfg.ReplaceAllowedIPs = true
			peerCfg.AllowedIPs = []net.IPNet{
				*netipx.PrefixIPNet(netip.PrefixFrom(peerEvent.Address, peerEvent.Address.BitLen())),
			}
			peerCfg.PersistentKeepaliveInterval = peerEvent.PersistentKeepAliveInterval

			if peerEvent.Endpoint != "" {
				ip, parseErr := netip.ParseAddrPort(peerEvent.Endpoint)
				if parseErr != nil {
					err = multierr.Append(err, parseErr)

					return true
				}

				peerCfg.Endpoint = AsUDP(ip)
			}

			logger.Info("updating peer", zap.Stringer("public_key", peerEvent.PubKey), zap.Stringer("address", peerEvent.Address))
		} else {
			logger.Info("removing peer", zap.Stringer("public_key", peerEvent.PubKey))
		}

		peers = append(peers, peerCfg)

		return true
	})

	if len(peers) == 0 {
		return nil, err
	}

	return peers, err
}

func checkDuplicateUpdates(seq iter.Seq[PeerEvent], oldCfg *wgtypes.Device, logger *zap.Logger) iter.Seq[PeerEvent] {
	return iter.Filter(seq, func(peerEvent PeerEvent) bool {
		// check if this update can be skipped
		pubKey := peerEvent.PubKey.String()

		for _, oldPeer := range oldCfg.Peers {
			if oldPeer.PublicKey.String() == pubKey {
				if len(oldPeer.AllowedIPs) != 1 {
					break
				}

				if peerEvent.Remove {
					return true
				}

				if prefix, ok := netipx.FromStdIPNet(&oldPeer.AllowedIPs[0]); ok {
					if prefix.Addr() == peerEvent.Address && // check address match & keepalive settings match
						(peerEvent.PersistentKeepAliveInterval == nil || pointer.SafeDeref(peerEvent.PersistentKeepAliveInterval) == oldPeer.PersistentKeepaliveInterval) {
						// skip the update
						logger.Info("skipping peer update", zap.String("public_key", pubKey))

						return false
					}
				}

				break
			}
		}

		// the peer wasn't found in the existing peers, so skip it
		if peerEvent.Remove {
			logger.Info("skipping peer remove", zap.String("public_key", pubKey))

			return false
		}

		return true
	})
}
