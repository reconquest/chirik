package main

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/reconquest/karma-go"

	"chirik/internal/audio"
	"chirik/internal/proto"
)

const (
	exitUsage         = 2
	clientQueueSize   = 8
	clientWorkerCount = 3
)

type clientOptions struct {
	transport    *transport
	config       config
	local        *net.UDPAddr
	playbackOpen func(string) (audio.PlaybackWriter, error)
	stdout       io.Writer
	stderr       io.Writer
	logger       *log.Logger
	debug        bool
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	command := ""
	if len(args) > 0 {
		command = args[0]
	}

	switch command {
	case "chirp":
		return chirpRun(args[1:], stdout, stderr)

	case "exchange":
		return exchangeRun(args[1:], stderr, stdout)

	default:
		_, code := argumentsParse(usageText, args, stdout, stderr)

		return code
	}
}

func chirpRun(args []string, stdout, stderr io.Writer) int {
	output := configParseOutput{stdout: stdout}

	cfg, ok := configParse(args, stderr, &output)
	if !ok {
		return output.code
	}

	logger := loggerNew(stderr)

	device, err := chirpAudioOpen(&cfg)
	if err != nil {
		logger.Print("ERROR ", karma.Format(err, "audio startup"))

		return 1
	}
	defer device.Close()

	transport, local, err := chirpTransportStart(&cfg)
	if err != nil {
		logger.Print("ERROR ", karma.Format(err, "UDP startup"))

		return 1
	}
	defer chirpTransportClose(transport, logger)

	ctx, stop, term, err := chirpTerminalStart()
	if err != nil {
		logger.Print("ERROR ", karma.Format(err, "terminal raw mode"))

		return 1
	}
	defer stop()

	defer terminalRestore(term, logger)

	options := chirpClientOptions(
		transport, &cfg, local, device, stdout, stderr, logger,
	)

	client, err := chirpClientNew(ctx, &options)
	if err != nil {
		logger.Print("ERROR ", karma.Format(err, "chirp initialization"))

		return 1
	}

	err = chirpClientRun(ctx, stop, client, device, term)
	if err != nil && !errors.Is(err, context.Canceled) {
		logger.Print("ERROR ", karma.Format(err, "chirp"))

		return 1
	}

	logger.Print("INFO chirp stopped")

	return 0
}

func chirpAudioOpen(cfg *config) (*audio.Device, error) {
	details := karma.Describe("source", cfg.source).Describe("sink", cfg.sink)

	err := audio.Check(cfg.source, cfg.sink)
	if err != nil {
		return nil, details.Format(err, "check audio devices")
	}

	device, err := audio.Open(cfg.source, cfg.sink)
	if err != nil {
		return nil, details.Format(err, "open audio device")
	}

	return device, nil
}

func chirpTransportStart(cfg *config) (*transport, *net.UDPAddr, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return nil, nil, karma.Format(err, "create UDP socket")
	}

	transport := transportStart(conn)

	local, err := localEndpoint(conn, cfg.peerex)
	if err != nil {
		_ = transport.close()

		return nil, nil, err
	}

	return transport, local, nil
}

func chirpTransportClose(transport *transport, logger *log.Logger) {
	err := transport.close()
	if err != nil {
		logger.Print("ERROR ", karma.Format(err, "UDP transport shutdown"))
	}
}

func terminalRestore(term *terminal, logger *log.Logger) {
	if term == nil {
		return
	}

	err := term.restore()
	if err != nil {
		logger.Print("ERROR ", karma.Format(err, "terminal restore"))
	}
}

func chirpClientOptions(
	transport *transport,
	cfg *config,
	local *net.UDPAddr,
	device *audio.Device,
	stdout, stderr io.Writer,
	logger *log.Logger,
) clientOptions {
	return clientOptions{
		transport: transport,
		config:    *cfg,
		local:     local,
		playbackOpen: func(name string) (audio.PlaybackWriter, error) {
			return device.PlaybackOpen(name)
		},
		stdout: stdout,
		stderr: stderr,
		logger: logger,
		debug:  os.Getenv("CHIRIK_DEBUG") != "",
	}
}

func chirpClientNew(
	ctx context.Context,
	options *clientOptions,
) (*client, error) {
	client := &client{
		ctx:          ctx,
		t:            options.transport,
		cfg:          options.config,
		local:        options.local,
		playbackOpen: options.playbackOpen,
		output:       &output{writer: options.stdout, logger: options.logger},
		logger:       options.logger,
		debug:        options.debug,
		stderr:       options.stderr,
		links:        make(map[string][]*link),
		seen:         map[proto.Handle]struct{}{options.config.handle: {}},
		frames:       make(chan []byte, clientQueueSize),
		commands:     make(chan byte, clientQueueSize),
		events:       make(chan error, clientQueueSize),
		readyCh:      make(chan struct{}),
	}
	client.discoveryEnsure()

	initial, err := client.initialLink()
	if err != nil {
		return nil, err
	}

	client.linkAdd(initial)

	err = client.linkKEXSend(initial, time.Now())
	if err != nil {
		return nil, err
	}

	return client, nil
}

func chirpClientRun(
	ctx context.Context,
	stop context.CancelFunc,
	client *client,
	device *audio.Device,
	term *terminal,
) error {
	workers := clientWorkersStart(ctx, client, device, term)
	err := client.run()

	stop()
	device.Close()
	workers.Wait()
	client.close()
	client.output.lineClear()

	outputErr := client.output.writeError()
	if err == nil && outputErr != nil {
		return outputErr
	}

	return err
}

func clientWorkersStart(
	ctx context.Context,
	client *client,
	device *audio.Device,
	term *terminal,
) *sync.WaitGroup {
	workers := &sync.WaitGroup{}
	workers.Add(clientWorkerCount)

	go captureRun(
		ctx,
		workers,
		client.events,
		client.frames,
		device.Capture,
		&client.muted,
	)
	go keyboardRun(ctx, workers, client.events, client.commands, term)
	go audioMonitor(ctx, workers, client.events, device)

	return workers
}
