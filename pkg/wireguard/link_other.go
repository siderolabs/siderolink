// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build !linux

package wireguard

import "fmt"

var ErrUnsupportedOS = fmt.Errorf("unsupported OS")

func createWireguardDevice(_ string) (string, error) {
	return "", ErrUnsupportedOS
}

func deleteWireguardDevice(_ string) error {
	return ErrUnsupportedOS
}
