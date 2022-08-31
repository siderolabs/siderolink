// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package events_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"github.com/talos-systems/talos/pkg/machinery/api/machine"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	eventsapi "github.com/talos-systems/siderolink/api/events"
	"github.com/talos-systems/siderolink/pkg/events"
)

type state struct {
	ConfigLoadError       error
	ConfigValidationError error
	Hostname              string
	Addresses             []string

	version int
	stateMu sync.Mutex
}

// HandleEvent implements events.Adapter.
func (s *state) HandleEvent(ctx context.Context, e events.Event) error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()

	if e.Node == "" {
		return fmt.Errorf("node address information is empty")
	}

	switch msg := e.Payload.(type) {
	case *machine.AddressEvent:
		s.Addresses = msg.Addresses
		s.Hostname = msg.Hostname
	case *machine.ConfigValidationErrorEvent:
		s.ConfigValidationError = fmt.Errorf(msg.Error)
	case *machine.ConfigLoadErrorEvent:
		s.ConfigLoadError = fmt.Errorf(msg.Error)
	}

	s.version++

	return nil
}

type SinkSuite struct {
	suite.Suite

	server *grpc.Server
	sink   *events.Sink
	lis    net.Listener
	eg     errgroup.Group
	state  *state
	sock   string
}

func (suite *SinkSuite) SetupSuite() {
	dir := suite.T().TempDir()
	suite.sock = filepath.Join(dir, "grpc.sock")
	lis, err := net.Listen("unix", suite.sock)
	suite.Require().NoError(err)

	suite.state = &state{}

	suite.sink = events.NewSink(suite.state)

	suite.lis = lis

	suite.server = grpc.NewServer()
	eventsapi.RegisterEventSinkServiceServer(suite.server, suite.sink)

	suite.eg.Go(func() error {
		return suite.server.Serve(lis)
	})
}

func (suite *SinkSuite) TearDownSuite() {
	suite.server.Stop()

	if err := suite.eg.Wait(); err != nil {
		suite.Require().True(errors.Is(err, grpc.ErrServerStopped))
	}
}

func (suite *SinkSuite) TestPublish() {
	conn, err := grpc.Dial(fmt.Sprintf("unix://%s", suite.sock), grpc.WithTransportCredentials(insecure.NewCredentials()))
	suite.Require().NoError(err)

	defer conn.Close() //nolint:errcheck

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := eventsapi.NewEventSinkServiceClient(conn)

	suite.Require().NoError(err)

	hostname := "localhost"
	addrs := []string{"127.0.0.2", "172.24.0.2"}
	eventErr := "it failed"

	events := []proto.Message{
		&machine.AddressEvent{
			Hostname:  hostname,
			Addresses: addrs,
		},
		&machine.ConfigLoadErrorEvent{
			Error: eventErr,
		},
		&machine.ConfigValidationErrorEvent{
			Error: eventErr,
		},
	}

	for i, e := range events {
		msg, err := anypb.New(e)
		suite.Require().NoError(err)

		ev := &eventsapi.EventRequest{
			Data: msg,
			Id:   fmt.Sprintf("%d", i),
		}

		_, err = client.Publish(ctx, ev)

		suite.Require().NoError(err)
	}

	for i := 0; i < 10; i++ {
		suite.state.stateMu.Lock()
		if suite.state.version == 2 {
			break
		}
		suite.state.stateMu.Unlock()

		time.Sleep(time.Millisecond * 100)
	}

	suite.state.stateMu.Lock()
	defer suite.state.stateMu.Unlock()

	suite.Require().Equal(hostname, suite.state.Hostname)
	suite.Require().Equal(addrs, suite.state.Addresses)
	suite.Require().EqualError(suite.state.ConfigValidationError, eventErr)
	suite.Require().EqualError(suite.state.ConfigLoadError, eventErr)
}

func TestSinkSuite(t *testing.T) {
	suite.Run(t, &SinkSuite{})
}
