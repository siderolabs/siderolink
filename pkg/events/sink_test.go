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
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	eventsapi "github.com/siderolabs/siderolink/api/events"
	pb "github.com/siderolabs/siderolink/api/siderolink"
	"github.com/siderolabs/siderolink/pkg/events"
)

type state struct {
	NodeUUIDs       []string
	ServerAddresses []string
	ServerEndpoints []string

	version int
	stateMu sync.Mutex
}

// HandleEvent implements events.Adapter.
func (s *state) HandleEvent(_ context.Context, e events.Event) error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()

	if e.Node == "" {
		return fmt.Errorf("node address information is empty")
	}

	switch msg := e.Payload.(type) {
	case *pb.ProvisionRequest:
		s.NodeUUIDs = append(s.NodeUUIDs, msg.NodeUuid)
	case *pb.ProvisionResponse:
		if ep := msg.GetEndpoints(); ep != nil {
			s.ServerEndpoints = append(s.ServerEndpoints, ep...)
		}

		if msg.ServerAddress != "" {
			s.ServerAddresses = append(s.ServerAddresses, msg.ServerAddress)
		}
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

	// we need any protobuf messages for tests, so use siderolink API as a mock
	suite.sink = events.NewSink(suite.state, []proto.Message{
		&pb.ProvisionRequest{},
		&pb.ProvisionResponse{},
	})

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

	events := []proto.Message{
		&pb.ProvisionRequest{
			NodeUuid: "1234",
		},
		&pb.ProvisionResponse{
			ServerAddress: "foo",
		},
		&pb.ProvisionResponse{
			ServerEndpoint: []string{"bar:123"},
		},
	}

	for i, e := range events {
		msg, err := anypb.New(e)
		suite.Require().NoError(err)

		ev := &eventsapi.EventRequest{
			Data: msg,
			Id:   strconv.Itoa(i),
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

	suite.Require().Equal([]string{"1234"}, suite.state.NodeUUIDs)
	suite.Require().Equal([]string{"foo"}, suite.state.ServerAddresses)
	suite.Require().Equal([]string{"bar:123"}, suite.state.ServerEndpoints)
}

func TestSinkSuite(t *testing.T) {
	suite.Run(t, &SinkSuite{})
}
