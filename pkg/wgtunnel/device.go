// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package wgtunnel provides a WireGuard tunnel device.
package wgtunnel

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/device"

	"github.com/siderolabs/siderolink/pkg/openclose"
	"github.com/siderolabs/siderolink/pkg/tun"
	"github.com/siderolabs/siderolink/pkg/wgtunnel/wgbind"
	"github.com/siderolabs/siderolink/pkg/wireguard"
)

// TunnelDevice is a tunnel device.
type TunnelDevice struct {
	dev       *device.Device
	uapi      net.Listener
	ifaceName string
	logger    *zap.Logger

	openClose openclose.OpenClose
}

// NewTunnelDevice creates a new TunnelDevice.
func NewTunnelDevice(iface string, mtu int, queuePair *wgbind.QueuePair, logger *zap.Logger) (*TunnelDevice, error) {
	result := TunnelDevice{
		logger: logger,
	}

	createdTun, err := tun.CreateTUN(iface, mtu)
	if err != nil {
		return nil, fmt.Errorf("error creating tun device: %w", err)
	}

	defer func() {
		if result.dev != nil {
			// If we have a device, no need to close the tunnel
			// since device will close it for us.
			return
		}

		if tunErr := createdTun.Close(); tunErr != nil {
			logger.Error("error closing tun device", zap.Error(tunErr))
		}

		logger.Debug("closed tun device")
	}()

	successfullReturn := false

	result.dev = device.NewDevice(createdTun, wgbind.NewClientBind(queuePair, logger), wireguard.DeviceLogger(logger))
	defer func() {
		if successfullReturn {
			return
		}

		result.close()
	}()

	result.ifaceName, err = createdTun.Name()
	if err != nil {
		return nil, fmt.Errorf("error getting tun device name: %w", err)
	}

	result.uapi, err = wireguard.UAPIOpen(result.ifaceName)
	if err != nil {
		return nil, fmt.Errorf("error listening on uapi socket: %w", err)
	}

	successfullReturn = true

	return &result, nil
}

// Run runs the device.
func (td *TunnelDevice) Run() error {
	ok, closeFn := td.openClose.Open(nil)
	if !ok {
		return errors.New("device already running/closed")
	}

	var wg sync.WaitGroup

	defer func() {
		wg.Wait()

		closeFn()
	}()

	for {
		unixSock, err := td.uapi.Accept()
		if errors.Is(err, net.ErrClosed) {
			if td.openClose.IsCloseRequested() {
				return nil
			}

			return err
		} else if err != nil {
			continue
		}

		wg.Add(1)

		go func() {
			defer wg.Done()

			td.dev.IpcHandle(unixSock)
		}()
	}
}

// Close closes the device and waits for it to stop.
func (td *TunnelDevice) Close() {
	if td == nil {
		return
	}

	td.openClose.RequestCloseWait(td.close)
}

func (td *TunnelDevice) close() {
	td.logger.Info("closing grpc tunnel device")
	defer td.logger.Info("grpc tunnel device closed")

	if td.dev != nil {
		td.dev.Close()
	}

	if td.uapi != nil {
		if err := td.uapi.Close(); err != nil {
			td.logger.Error("error closing uapi socket", zap.Error(err))
		}
	}
}

// IsClosed returns true if the device is closed.
func (td *TunnelDevice) IsClosed() bool {
	return td == nil || td.openClose.IsClosed()
}

// IfaceName returns the name of the interface.
func (td *TunnelDevice) IfaceName() string {
	if td == nil {
		return "<invalid_device>"
	}

	return td.ifaceName
}
