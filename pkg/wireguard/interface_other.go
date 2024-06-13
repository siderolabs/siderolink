// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build !darwin

package wireguard

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	netip "net/netip"

	"github.com/jsimonetti/rtnetlink/v2/rtnl"
	"go4.org/netipx"
)

// InterfaceName is the name of the WireGuard interface.
const InterfaceName = "siderolink"

// LinkUp brings the WireGuard interface up.
func LinkUp(iface *net.Interface) error {
	rtnlClient, err := rtnl.Dial(nil)
	if err != nil {
		return fmt.Errorf("error initializing netlink client: %w", err)
	}

	defer rtnlClient.Close() //nolint:errcheck

	return rtnlClient.LinkUp(iface)
}

func addIPToInterface(iface *net.Interface, ipNet *net.IPNet) error {
	rtnlClient, err := rtnl.Dial(nil)
	if err != nil {
		return fmt.Errorf("error initializing netlink client: %w", err)
	}

	defer rtnlClient.Close() //nolint:errcheck

	err = rtnlClient.AddrAdd(iface, ipNet)
	if err != nil && errors.Is(err, fs.ErrExist) {
		err = nil
	}

	return err
}

func removeIPFromInterface(iface *net.Interface, ipNet netip.Prefix) error {
	ipnet := netipx.PrefixIPNet(ipNet)

	rtnlClient, err := rtnl.Dial(nil)
	if err != nil {
		return fmt.Errorf("error initializing netlink client: %w", err)
	}

	defer rtnlClient.Close() //nolint:errcheck

	err = rtnlClient.AddrDel(iface, ipnet)
	if err != nil {
		return err
	}

	return nil
}
