// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package events contains events sink gRPC server implementation.
package events

import "google.golang.org/protobuf/proto"

// Event as received from the API.
type Event struct {
	Payload proto.Message
	TypeURL string
	ID      string
}
