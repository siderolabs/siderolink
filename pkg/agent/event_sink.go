// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package agent

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"gopkg.in/yaml.v3"

	eventsapi "github.com/siderolabs/siderolink/api/events"
	"github.com/siderolabs/siderolink/pkg/events"
)

type adapter struct{}

// HandleEvent implements events.Adapter.
func (s *adapter) HandleEvent(_ context.Context, e events.Event) error {
	data, err := yaml.Marshal(e.Payload)
	if err != nil {
		return err
	}

	log.Printf("Node: %s, Event: %s, ID: %s, Payload: \n\t%s", e.Node, e.TypeURL, e.ID, strings.Join(strings.Split(string(data), "\n"), "\n\t"))

	return nil
}

func eventSink(ctx context.Context, apiEndpoint string, eg *errgroup.Group) error {
	listen, err := net.Listen("tcp", apiEndpoint)
	if err != nil {
		return fmt.Errorf("error listening for gRPC eventsink API: %w", err)
	}

	server := grpc.NewServer()

	sink := events.NewSink(&adapter{}, nil)
	eventsapi.RegisterEventSinkServiceServer(server, sink)

	stopServer := sync.OnceFunc(server.Stop)

	eg.Go(func() error {
		defer stopServer()

		return server.Serve(listen)
	})

	context.AfterFunc(ctx, stopServer)

	return nil
}
