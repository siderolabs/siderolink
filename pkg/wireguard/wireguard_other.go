// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build !windows

package wireguard

import (
	"fmt"
	"net"

	"golang.zx2c4.com/wireguard/ipc"
)

// UAPIOpen opens a UAPI socket.
func UAPIOpen(interfaceName string) (net.Listener, error) {
	fileUAPI, err := ipc.UAPIOpen(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("error listening on UAPI socket: %w", err)
	}

	uapi, err := ipc.UAPIListen(interfaceName, fileUAPI)
	if err != nil {
		return nil, fmt.Errorf("error listening on uapi socket: %w", err)
	}

	return uapi, nil
}
