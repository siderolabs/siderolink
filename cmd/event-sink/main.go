// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"gopkg.in/yaml.v3"

	eventsapi "github.com/talos-systems/siderolink/api/events"
	"github.com/talos-systems/siderolink/pkg/events"
)

var flags struct {
	address string
	port    int
}

type adapter struct{}

// HandleEvent implements events.Adapter.
func (s *adapter) HandleEvent(e events.Event) error {
	data, err := yaml.Marshal(e.Payload)
	if err != nil {
		return err
	}

	log.Printf("Event: %s, ID: %s, Payload: \n\t%s", e.TypeURL, e.ID, strings.Join(strings.Split(string(data), "\n"), "\n\t"))

	return nil
}

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "event-sink",
	Short: "Reference implementation for the event sink server",
	Long:  ``,
	RunE: func(cmd *cobra.Command, args []string) error {
		listen, err := net.Listen("tcp", fmt.Sprintf("%s:%d", flags.address, flags.port))
		if err != nil {
			return err
		}

		server := grpc.NewServer()

		ctx, _ := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

		var eg errgroup.Group

		eg.Go(func() error {
			<-ctx.Done()
			server.Stop()

			return nil
		})

		sink := events.NewSink(&adapter{})
		eventsapi.RegisterEventSinkServiceServer(server, sink)

		eg.Go(func() error {
			return server.Serve(listen)
		})

		if err = eg.Wait(); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			return err
		}

		return nil
	},
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().IntVarP(&flags.port, "port", "p", 8080, "Start gRPC server on the defined port.")
	rootCmd.Flags().StringVar(&flags.address, "address", "0.0.0.0", "Start gRPC server on the defined address.")
}
