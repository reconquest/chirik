package main

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/reconquest/karma-go"

	sessioncrypto "chirik/internal/crypto"
	"chirik/internal/proto"
)

const exchangeUsageText = `Run peer discovery and relay fallback.

Usage:
  chirik exchange <listen-address>
  chirik exchange -h | --help

Arguments:
  listen-address  IPv4 host and non-zero UDP port to listen on.
                  Use 0:<port> to listen on all IPv4 interfaces.

Options:
  -h, --help  Show this help.

Operation:
  The exchange generates an ephemeral X25519 key pair at startup and logs
  its public key. Restarting the exchange generates a different key pair.
  Ctrl-C and SIGTERM stop the exchange.

Example:
  chirik exchange 0:7777
`

type exchangeServer struct {
	conn            *net.UDPConn
	logger          *log.Logger
	pair            *sessioncrypto.KeyPair
	entries         map[string]map[proto.Handle]*exchangeEntry
	sessions        map[string][]*exchangeSession
	discovery       *discoveryEngine
	endpointRecords func(
		*net.UDPAddr,
		*net.UDPAddr,
		proto.Handle,
	) []proto.PeerRecord
	mu sync.Mutex
}

func exchangeRun(args []string, stderr io.Writer, outputs ...io.Writer) int {
	stdout := io.Writer(os.Stdout)
	if len(outputs) > 0 {
		stdout = outputs[0]
	}

	arguments, code := argumentsParse(exchangeUsageText,
		append([]string{"exchange"}, args...), stdout, stderr)
	if arguments == nil {
		return code
	}

	logger := loggerNew(stderr)

	addr, err := exchangeAddrResolve(arguments.ValueListen)
	if err != nil {
		logger.Print("ERROR ", karma.
			Describe("address", arguments.ValueListen).
			Format(err, "exchange address resolution"),
		)

		return 1
	}

	if addr.Port == 0 {
		logger.Print("ERROR exchange address rejected: port must be non-zero")

		return 1
	}

	server, err := exchangeServerStart(addr, logger)
	if err != nil {
		logger.Print("ERROR ", karma.
			Describe("address", addr).
			Format(err, "exchange startup"),
		)

		return 1
	}
	defer exchangeListenerClose(server, logger)

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	err = server.run(ctx)

	stop()

	if err != nil {
		logger.Print("ERROR ", karma.Format(err, "exchange"))

		return 1
	}

	logger.Print("INFO exchange stopped")

	return 0
}

func exchangeServerStart(
	addr *net.UDPAddr,
	logger *log.Logger,
) (*exchangeServer, error) {
	pair, err := sessioncrypto.KeyPairGenerate()
	if err != nil {
		return nil, karma.Format(err, "generate exchange key pair")
	}

	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return nil, karma.Format(err, "listen for exchange datagrams")
	}

	server := &exchangeServer{
		conn:     conn,
		logger:   logger,
		pair:     pair,
		entries:  make(map[string]map[proto.Handle]*exchangeEntry),
		sessions: make(map[string][]*exchangeSession),
	}
	server.discoveryEnsure()

	public := pair.Public()
	logger.Print("INFO ", karma.
		Describe("address", conn.LocalAddr()).
		Describe("public_key", base64.StdEncoding.EncodeToString(public[:])).
		Format(nil, "exchange started"),
	)

	return server, nil
}

func exchangeListenerClose(server *exchangeServer, logger *log.Logger) {
	err := server.conn.Close()
	if err != nil && !errors.Is(err, net.ErrClosed) {
		logger.Print("ERROR ", karma.Format(err, "exchange listener shutdown"))
	}
}

func (server *exchangeServer) run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	closeConn := context.AfterFunc(ctx, func() { _ = server.conn.Close() })

	defer closeConn()

	var workers sync.WaitGroup

	workers.Add(1)

	go func() {
		defer workers.Done()

		server.sweepLoop(ctx.Done())
	}()

	err := server.serve()

	cancel()

	closeErr := server.conn.Close()

	workers.Wait()

	if err == nil && closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
		return karma.Format(closeErr, "close exchange listener")
	}

	return err
}

func exchangeAddrResolve(raw string) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return nil, karma.Format(err, "split exchange address")
	}

	if host == "0" {
		raw = net.JoinHostPort("0.0.0.0", port)
	}

	addr, err := net.ResolveUDPAddr("udp4", raw)
	if err != nil {
		return nil, karma.Format(err, "resolve exchange address")
	}

	return addr, nil
}

func (server *exchangeServer) serve() error {
	buffer := make([]byte, proto.MaxDatagram+1)
	for {
		readCount, addr, err := server.conn.ReadFromUDP(buffer)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}

			return karma.Format(err, "read exchange datagram")
		}

		if readCount > proto.MaxDatagram {
			continue
		}

		server.handle(buffer[:readCount], addr, time.Now())
	}
}

func (server *exchangeServer) handle(
	packet []byte,
	addr *net.UDPAddr,
	now time.Time,
) {
	if public, ok := proto.KEXParse(packet); ok {
		server.kexHandle(addr, public, now)

		return
	}

	server.encryptedHandle(addr, packet, now)
}
