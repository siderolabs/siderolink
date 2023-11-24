// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package pb provides protobuf definitions for the SideroLink API.
package pb

import (
	"errors"
	"slices"
)

// MakeEndpoints sets the endpoints.
func MakeEndpoints(endpoints ...string) []string {
	if len(endpoints) == 0 {
		panic(errors.New("no endpoints provided"))
	}

	// To preserve GRPC backwards compatibility, we put the first endpoint at the end.
	if len(endpoints) > 1 {
		endpoints[0], endpoints[len(endpoints)-1] = endpoints[len(endpoints)-1], endpoints[0]
	}

	return endpoints
}

// GetEndpoints returns the endpoints.
func (m *ProvisionResponse) GetEndpoints() []string {
	if m == nil || len(m.ServerEndpoint) == 0 {
		return nil
	}

	endpoints := slices.Clone(m.ServerEndpoint)

	// To preserve GRPC backwards compatibility, we put the first endpoint at the end.
	if len(endpoints) > 1 {
		endpoints[0], endpoints[len(endpoints)-1] = endpoints[len(endpoints)-1], endpoints[0]
	}

	return endpoints
}
