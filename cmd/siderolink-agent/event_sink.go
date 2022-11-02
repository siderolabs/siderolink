// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package main ...
package main

import (
	"context"
	"log"
	"net"
	"strings"

	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"gopkg.in/yaml.v3"

	eventsapi "github.com/siderolabs/siderolink/api/events"
	"github.com/siderolabs/siderolink/pkg/events"
)

var eventSinkFlags struct {
	apiEndpoint string
}

type adapter struct{}

// HandleEvent implements events.Adapter.
func (s *adapter) HandleEvent(ctx context.Context, e events.Event) error {
	data, err := yaml.Marshal(e.Payload)
	if err != nil {
		return err
	}

	log.Printf("Node: %s, Event: %s, ID: %s, Payload: \n\t%s", e.Node, e.TypeURL, e.ID, strings.Join(strings.Split(string(data), "\n"), "\n\t"))

	return nil
}

func eventSink(ctx context.Context, eg *errgroup.Group) error {
	listen, err := net.Listen("tcp", eventSinkFlags.apiEndpoint)
	if err != nil {
		return err
	}

	server := grpc.NewServer()

	eg.Go(func() error {
		<-ctx.Done()
		server.Stop()

		return nil
	})

	sink := events.NewSink(&adapter{}, nil)
	eventsapi.RegisterEventSinkServiceServer(server, sink)

	eg.Go(func() error {
		return server.Serve(listen)
	})

	return nil
}
