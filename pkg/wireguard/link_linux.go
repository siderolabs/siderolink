// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build linux

package wireguard

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/jsimonetti/rtnetlink/v2"
	"golang.org/x/sys/unix"
)

func createWireguardDevice(name string) (string, error) {
	c, err := rtnetlink.Dial(nil)
	if err != nil {
		return "", fmt.Errorf("error connecting to netlink: %w", err)
	}

	defer c.Close() //nolint:errcheck

	err = c.Link.New(&rtnetlink.LinkMessage{
		Family: unix.AF_UNSPEC,
		Type:   unix.ARPHRD_NONE,
		Attributes: &rtnetlink.LinkAttributes{
			Name: name,
			Type: 65534,
			Info: &rtnetlink.LinkInfo{
				Kind: linkKindWireguard,
			},
			MTU: LinkMTU,
		},
	})
	if err != nil && !errors.Is(err, fs.ErrExist) {
		return "", fmt.Errorf("error creating wireguard device: %w", err)
	}

	allLinks, err := c.Link.List()
	if err != nil {
		return "", fmt.Errorf("error listing links: %w", err)
	}

	var linkIdx uint32

	for _, linkMessage := range allLinks {
		if linkMessage.Attributes.Name == name {
			linkIdx = linkMessage.Index

			break
		}
	}

	if linkIdx == 0 {
		return "", fmt.Errorf("wireguard device %s not found", name)
	}

	if err := func() error {
		for _, path := range []string{
			fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/forwarding", name),
			fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/forwarding", name),
		} {
			if err := os.MkdirAll(filepath.Dir(path), 0o644); err != nil {
				return err
			}

			if err := os.WriteFile(path, []byte("0\n"), 0o644); err != nil {
				return err
			}
		}

		return nil
	}(); err != nil {
		// try to clean up the created link
		c.Link.Delete(linkIdx) //nolint:errcheck

		return "", fmt.Errorf("error writing sysctl files: %w", err)
	}

	return name, nil
}

func deleteWireguardDevice(name string) error {
	c, err := rtnetlink.Dial(nil)
	if err != nil {
		return err
	}

	defer c.Close() //nolint:errcheck

	kind, err := c.Link.ListByKind(linkKindWireguard)
	if err != nil {
		return err
	}

	for _, linkMessage := range kind {
		if linkMessage.Attributes.Name == name {
			err = c.Link.Delete(linkMessage.Index)
			if err != nil {
				return err
			}

			break
		}
	}

	return nil
}
