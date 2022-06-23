// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build !darwin

package wireguard

import (
	"fmt"
	"net"

	"github.com/jsimonetti/rtnetlink/rtnl"
)

const interfaceName = "siderolink"

func linkUp(iface *net.Interface) error {
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

	return rtnlClient.AddrAdd(iface, ipNet)
}
