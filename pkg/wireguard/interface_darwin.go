// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build darwin

package wireguard

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
)

// InterfaceName is the name of the WireGuard interface.
//
// darwin requires tun devices to have the name utun[0-9]+ or just utun for the kernel to select one automatically.
// See https://github.com/WireGuard/wireguard-go/blob/master/README.md#macos for more details.
const InterfaceName = "utun"

// LinkUp brings the WireGuard interface up.
func LinkUp(iface *net.Interface) error {
	return exec.Command("ifconfig", iface.Name, "up").Run()
}

func addIPToInterface(iface *net.Interface, ipNet *net.IPNet) error {
	isv6 := ipNet.IP.To4() == nil

	inet := "inet"
	if isv6 {
		inet = "inet6"
	}

	cmdAndArgs := []string{"ifconfig", iface.Name, inet, ipNet.String()}

	err := exec.Command(cmdAndArgs[0], cmdAndArgs[1:]...).Run()
	if err != nil {
		return fmt.Errorf("error running command %q: %w", cmdAndArgs, err)
	}

	return nil
}

func removeIPFromInterface(iface *net.Interface, ipNet netip.Prefix) error {
	inet := "inet"
	if ipNet.Addr().Is6() {
		inet = "inet6"
	}

	cmdAndArgs := []string{"ifconfig", iface.Name, inet, ipNet.String(), "delete"}

	err := exec.Command(cmdAndArgs[0], cmdAndArgs[1:]...).Run()
	if err != nil {
		return fmt.Errorf("error running command %q: %w", cmdAndArgs, err)
	}

	return nil
}
