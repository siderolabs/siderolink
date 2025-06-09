// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package wggrpc_test

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"runtime/pprof"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"golang.org/x/sync/errgroup"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/siderolabs/siderolink/api/siderolink"
	"github.com/siderolabs/siderolink/pkg/wgtunnel/wgbind"
	"github.com/siderolabs/siderolink/pkg/wgtunnel/wggrpc"
	"github.com/siderolabs/siderolink/pkg/wireguard"
)

func TestService(t *testing.T) {
	defer pprof.Lookup("goroutine").WriteTo(os.Stderr, 1) //nolint:errcheck

	ctx, cancel := signal.NotifyContext(t.Context(), os.Interrupt)
	defer cancel()

	eg, ctx := errgroup.WithContext(ctx)

	pt := wgbind.NewPeerTraffic(1)
	ap := wggrpc.NewAllowedPeers()

	logger := zaptest.NewLogger(t, zaptest.Level(zap.DebugLevel))

	serviceStop := startService(t, pt, ap, eg, logger)
	defer serviceStop()

	clientCtx, clientCancel := context.WithCancel(ctx)
	defer clientCancel()

	t.Run("several_clients", func(t *testing.T) {
		const maxClients = 2

		var waitG sync.WaitGroup

		waitG.Add(maxClients)

		t.Run("monitor", func(t *testing.T) {
			t.Parallel()

			waitG.Wait()
			clientCancel()
		})

		nps := wireguard.VirtualNetworkPrefix()

		for client := range maxClients {
			client := "client_" + strconv.Itoa(client)

			clientAddr := getClientAddrPort(nps)
			clientKey, err := wgtypes.GenerateKey()
			require.NoError(t, err)

			ap.AddToken(clientKey.PublicKey(), clientAddr.Addr().String())

			t.Run(client, func(t *testing.T) {
				defer ap.RemoveToken(clientKey.PublicKey())
				defer waitG.Done()

				t.Parallel()

				testClient(clientCtx, t, eg, clientAddr, logger.With(zap.String("client", client)))
			})
		}

		t.Run("server", func(t *testing.T) {
			t.Parallel()

			testServer(clientCtx, t, pt, logger.With(zap.String("server", "server")))
		})
	})

	t.Log("waiting for clients to finish")

	serviceStop()
	cancel()

	err := eg.Wait()

	if !errors.Is(err, context.Canceled) || !errors.Is(err, context.DeadlineExceeded) {
		require.NoError(t, err)
	}
}

func testServer(ctx context.Context, t *testing.T, pt *wgbind.PeerTraffic, l *zap.Logger) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		data, err := pt.PopRecvData(ctx)
		if err != nil {
			return
		}

		l.Debug("service got packet", zap.String("src", data.Addr), zap.ByteString("data", data.Packet.Data))

		strData := string(data.Packet.Data)

		pushToQueue := func(ctx context.Context, addr string, data []byte) error {
			q, ok := pt.GetSendQueue(addr, false)
			require.True(t, ok)

			return q.Push(ctx, data)
		}

		switch strData {
		case "hello":
			require.NoError(t, pushToQueue(ctx, data.Addr, []byte("world")))
		case "first thing":
			require.NoError(t, pushToQueue(ctx, data.Addr, []byte("first thing response")))
		case "second thing":
			require.NoError(t, pushToQueue(ctx, data.Addr, []byte("second thing response")))
		case "third thing":
			require.NoError(t, pushToQueue(ctx, data.Addr, []byte("third thing response")))
		}
	}
}

func testClient(ctx context.Context, t *testing.T, eg *errgroup.Group, ourAddr netip.AddrPort, logger *zap.Logger) {
	conn := createConn(t, "127.0.0.1:10888")
	qp := wgbind.NewQueuePair(10, 2)

	relay := wggrpc.NewRelay(conn, 5*time.Second, qp, ourAddr)

	defer func() {
		relay.Close()

		require.True(t, relay.IsClosed())
	}()

	eg.Go(func() error {
		return relay.Run(ctx, logger)
	})

	clientPushMessage := clientPushMessageFunc(ctx, qp)
	clientPopMessage := clientPopMessageFunc(ctx, t, qp)

	require.NoError(t, clientPushMessage("hello"))
	require.Equal(t, "world", clientPopMessage())

	require.NoError(t, clientPushMessage("first thing"))
	require.NoError(t, clientPushMessage("second thing"))
	require.NoError(t, clientPushMessage("third thing"))

	require.Equal(t, "first thing response", clientPopMessage())
	require.Equal(t, "second thing response", clientPopMessage())
	require.Equal(t, "third thing response", clientPopMessage())
}

func startService(t *testing.T, pt *wgbind.PeerTraffic, ap *wggrpc.AllowedPeers, eg *errgroup.Group, logger *zap.Logger) func() {
	server := grpc.NewServer()
	srv := wggrpc.NewService(pt, ap, logger)

	pb.RegisterWireGuardOverGRPCServiceServer(server, srv)

	listen, err := net.Listen("tcp", "127.0.0.1:10888")
	require.NoError(t, err)

	eg.Go(func() error {
		return server.Serve(listen)
	})

	return sync.OnceFunc(func() {
		server.GracefulStop()

		srv.Wait()
	})
}

func createConn(t *testing.T, addr string) *grpc.ClientConn { //nolint:unparam
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, conn.Close())
	})

	return conn
}

func getClientAddrPort(nodePrefix netip.Prefix) netip.AddrPort {
	// generated random address for the node
	raw := nodePrefix.Addr().As16()
	salt := make([]byte, 8)

	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		panic(err)
	}

	copy(raw[8:], salt)

	return netip.AddrPortFrom(netip.PrefixFrom(netip.AddrFrom16(raw), nodePrefix.Bits()).Addr(), 50888)
}

func TestReplacingConnectionService(t *testing.T) {
	ctx, cancelS := signal.NotifyContext(t.Context(), os.Interrupt)
	defer cancelS()

	ctx, cancelFn := context.WithCancelCause(ctx)
	defer cancelFn(errors.New("test failed"))

	eg, ctx := errgroup.WithContext(ctx)

	pt := wgbind.NewPeerTraffic(1)
	ap := wggrpc.NewAllowedPeers()

	logger := zaptest.NewLogger(t, zaptest.Level(zap.DebugLevel))

	serviceStop := startService(t, pt, ap, eg, logger)
	defer serviceStop()

	ourAddr1 := getClientAddrPort(wireguard.VirtualNetworkPrefix())
	clientKey, err := wgtypes.GenerateKey()
	require.NoError(t, err)

	ap.AddToken(clientKey.PublicKey(), ourAddr1.Addr().String())

	defer ap.RemoveToken(clientKey.PublicKey())

	client1Ctx, client1Cancel := context.WithCancelCause(ctx)
	defer client1Cancel(nil)

	client2Ctx, client2Cancel := context.WithCancelCause(ctx)
	defer client2Cancel(nil)

	t.Run("testing_clients", func(t *testing.T) {
		client1ExchangeComplete := make(chan struct{})

		context.AfterFunc(client1Ctx, func() {
			<-client2Ctx.Done()

			cancelFn(errors.New("test completed successfully"))
		})

		t.Run("server", func(t *testing.T) {
			t.Parallel()

			testServer(ctx, t, pt, logger.With(zap.String("server", "server")))
		})

		t.Run("client_1", func(t *testing.T) {
			defer client1Cancel(nil)

			t.Parallel()

			conn := createConn(t, "127.0.0.1:10888")
			qp := wgbind.NewQueuePair(10, 2)

			go func() {
				relay := wggrpc.NewRelay(conn, 5*time.Second, qp, ourAddr1)

				relayErr := relay.Run(client1Ctx, logger)

				client1Cancel(relayErr)
			}()

			clientPushMessage := clientPushMessageFunc(client1Ctx, qp)
			clientPopMessage := clientPopMessageFunc(client1Ctx, t, qp)

			require.NoError(t, clientPushMessage("hello"))
			require.Equal(t, "world", clientPopMessage())

			close(client1ExchangeComplete)

			<-client1Ctx.Done()

			assert.ErrorIs(t, context.Cause(client1Ctx), wggrpc.ErrPeerReplaced)
		})

		t.Run("client_2", func(t *testing.T) {
			defer client2Cancel(nil)

			t.Parallel()

			<-client1ExchangeComplete

			conn := createConn(t, "127.0.0.1:10888")
			qp := wgbind.NewQueuePair(10, 2)

			go func() {
				relay := wggrpc.NewRelay(conn, 5*time.Second, qp, ourAddr1)

				relayErr := relay.Run(client2Ctx, logger)

				client2Cancel(relayErr)
			}()

			clientPushMessage := clientPushMessageFunc(client2Ctx, qp)
			clientPopMessage := clientPopMessageFunc(client2Ctx, t, qp)

			require.NoError(t, clientPushMessage("first thing"))
			require.Equal(t, "first thing response", clientPopMessage())
		})
	})

	t.Log("waiting for clients to finish")

	<-client1Ctx.Done()
	<-client2Ctx.Done()

	serviceStop()
	cancelFn(errors.New("should be canceled before"))

	require.ErrorIs(t, context.Cause(client1Ctx), wggrpc.ErrPeerReplaced)
	require.ErrorIs(t, context.Cause(client2Ctx), context.Canceled)
	require.EqualError(t, context.Cause(ctx), "test completed successfully")
	require.NoError(t, eg.Wait())
}

func clientPushMessageFunc(ctx context.Context, qp *wgbind.QueuePair) func(str string) error {
	return func(str string) error {
		return qp.ToPeer.Push(ctx, wgbind.Packet{
			Addr: "127.0.0.1:60001",
			Data: []byte(str),
		})
	}
}

func clientPopMessageFunc(ctx context.Context, t *testing.T, qp *wgbind.QueuePair) func() string {
	return func() string {
		packet, err := qp.FromPeer.Pop(ctx)
		require.NoError(t, err)

		return string(packet.Data)
	}
}

func TestNotAllowedPeer(t *testing.T) {
	ctx, cancel := signal.NotifyContext(t.Context(), os.Interrupt)
	defer cancel()

	eg, ctx := errgroup.WithContext(ctx)

	pt := wgbind.NewPeerTraffic(1)
	ap := wggrpc.NewAllowedPeers()

	logger := zaptest.NewLogger(t, zaptest.Level(zap.DebugLevel))

	serviceStop := startService(t, pt, ap, eg, logger)
	defer serviceStop()

	ourAddr1 := getClientAddrPort(wireguard.VirtualNetworkPrefix())

	clientCtx, clientCancel := context.WithCancelCause(ctx)
	defer clientCancel(nil)

	context.AfterFunc(clientCtx, cancel)

	t.Run("testing_client", func(t *testing.T) {
		t.Run("server", func(t *testing.T) {
			t.Parallel()

			testServer(ctx, t, pt, logger.With(zap.String("server", "server")))
		})

		t.Run("client", func(t *testing.T) {
			defer clientCancel(nil)

			t.Parallel()

			conn := createConn(t, "127.0.0.1:10888")
			qp := wgbind.NewQueuePair(10, 2)

			go func() {
				relay := wggrpc.NewRelay(conn, 5*time.Second, qp, ourAddr1)

				relayErr := relay.Run(ctx, logger)

				clientCancel(relayErr)
			}()

			<-clientCtx.Done()

			require.ErrorIs(t, context.Cause(clientCtx), wggrpc.ErrPeerNotAllowed)
		})
	})

	t.Log("waiting for clients to finish")

	<-clientCtx.Done()

	serviceStop()
	cancel()

	require.ErrorIs(t, context.Cause(clientCtx), wggrpc.ErrPeerNotAllowed)
	require.NoError(t, eg.Wait())
}
