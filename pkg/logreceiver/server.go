// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package logreceiver

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"

	"go.uber.org/zap"
	"inet.af/netaddr"
)

// Server implements TCP server to receive JSON logs.
type Server struct {
	listener net.Listener
	logger   *zap.Logger
	handler  Handler
}

// Handler is called for each received message.
type Handler func(srcAddress netaddr.IP, msg map[string]interface{})

// NewServer initializes new Server.
func NewServer(logger *zap.Logger, listener net.Listener, handler Handler) (*Server, error) {
	return &Server{
		listener: listener,
		logger:   logger,
		handler:  handler,
	}, nil
}

// Serve runs the TCP server loop.
func (srv *Server) Serve() error {
	for {
		conn, err := srv.listener.Accept()
		if err != nil {
			return fmt.Errorf("error accepting connection: %w", err)
		}

		go srv.handleConnection(conn)
	}
}

// Stop serving.
//
// This has a bug that it doesn't close the connections.
func (srv *Server) Stop() {
	srv.listener.Close() //nolint:errcheck
}

func (srv *Server) handleConnection(conn net.Conn) {
	defer conn.Close() //nolint:errcheck

	bufReader := bufio.NewReader(conn)
	decoder := json.NewDecoder(bufReader)

	srcAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		srv.logger.Error("error getting remote IP address")

		return
	}

	srcAddress, _ := netaddr.FromStdIP(srcAddr.IP)

	for {
		msg := map[string]interface{}{}

		if err := decoder.Decode(&msg); err != nil {
			if !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
				srv.logger.Error("error decoding message", zap.Error(err))
			}

			return
		}

		srv.handler(srcAddress, msg)
	}
}
