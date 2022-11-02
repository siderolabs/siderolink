// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package events

import (
	"context"

	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/proto"

	"github.com/siderolabs/siderolink/api/events"
)

// Adapter is an abstract event stream receiver.
type Adapter interface {
	HandleEvent(ctx context.Context, event Event) error
}

// Sink implements events.EventSinkServiceServer.
type Sink struct {
	events.UnimplementedEventSinkServiceServer
	adapter         Adapter
	supportedEvents map[string]proto.Message
}

// NewSink creates new events sink service.
func NewSink(a Adapter, supportedTypes []proto.Message) *Sink {
	sink := &Sink{
		adapter:         a,
		supportedEvents: make(map[string]proto.Message),
	}

	for _, eventType := range supportedTypes {
		sink.supportedEvents["type.googleapis.com/"+string(eventType.ProtoReflect().Descriptor().FullName())] = eventType
	}

	return sink
}

// Publish implements events.EventSinkServiceServer.
func (s *Sink) Publish(ctx context.Context, e *events.EventRequest) (*events.EventResponse, error) {
	var (
		typeURL = e.Data.TypeUrl
		res     = &events.EventResponse{}
	)

	msg := s.supportedEvents[typeURL]
	if msg == nil {
		// We haven't implemented the handling of this event yet.
		return res, nil
	}

	msg = proto.Clone(msg)

	if err := proto.Unmarshal(e.GetData().GetValue(), msg); err != nil {
		return res, err
	}

	var node string

	peer, ok := peer.FromContext(ctx)
	if ok {
		node = peer.Addr.String()
	}

	return res, s.adapter.HandleEvent(ctx, Event{
		Node:    node,
		TypeURL: typeURL,
		ID:      e.Id,
		Payload: msg,
	})
}
