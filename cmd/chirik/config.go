package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/kovetskiy/docopt-go"
	"github.com/reconquest/karma-go"

	"chirik/internal/proto"
)

const usageText = `chirik - encrypted voice group chat

Usage:
  chirik chirp <target> [options]
  chirik exchange <listen-address>
  chirik -h | --help

Commands:
  chirp      Join a voice channel through an exchange.
  exchange   Run an exchange for peer discovery and relay fallback.

Target:
  <handle>@<exchange-host>:<exchange-port>/<channel>

Options:
  -h, --help  Show this help.

Examples:
  chirik exchange 0:7777
  chirik chirp alice@exchange.example:7777/team-room

Run "chirik <command> --help" for command-specific options.
`

const chirpUsageText = `Join an encrypted voice channel through an exchange.

Usage:
  chirik chirp <target> [options]
  chirik chirp -h | --help

Target:
  <handle>@<exchange-host>:<exchange-port>/<channel>

  handle         1-255 ASCII letters and digits.
  exchange-host  IPv4 address or DNS name of the exchange.
  exchange-port  Non-zero UDP port of the exchange.
  channel        Non-empty channel name; quote whitespace for your shell.

Options:`

const chirpUsageSuffix = `
  --source=<name>  Pulse source name (empty selects the server default).
  --sink=<name>    Pulse sink name (empty selects the server default).
  -h, --help
        Show this help.

Interactive controls:
  m       Toggle microphone mute.
  q       Quit.
  Ctrl-C  Quit. SIGTERM also stops the process.

Environment:
  CHIRIK_DEBUG=1  Enable debug packet statistics.

Examples:
  chirik chirp alice@exchange.example:7777/team-room
  chirik chirp alice@127.0.0.1:7777/team-room \
    --source=<pulse-source-name> --sink=<pulse-sink-name>
`

type config struct {
	handle     proto.Handle
	channel    string
	channelKey [32]byte
	peerex     *net.UDPAddr
	source     string
	sink       string
}

type configParseOutput struct {
	stdout io.Writer
	code   int
}

type cliArguments struct {
	ModeChirp    bool   `docopt:"chirp"`
	ModeExchange bool   `docopt:"exchange"`
	ValueTarget  string `docopt:"<target>"`
	ValueSource  string `docopt:"--source"`
	ValueSink    string `docopt:"--sink"`
	ValueListen  string `docopt:"<listen-address>"`
}

func argumentsParse(
	usage string,
	args []string,
	stdout, stderr io.Writer,
) (*cliArguments, int) {
	code := 1
	parser := &docopt.Parser{
		HelpHandler: func(err error, text string) {
			writer := stdout

			code = 0

			if err != nil {
				writer = stderr
				code = exitUsage
			}

			_, writeErr := fmt.Fprintln(writer, text)
			if writeErr != nil {
				code = 1
			}
		},
	}

	if args == nil {
		args = []string{}
	}

	opts, err := parser.ParseArgs(usage, args, "")
	if err != nil || opts == nil {
		return nil, code
	}

	var arguments cliArguments

	err = opts.Bind(&arguments)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, karma.Format(err, "bind arguments"))

		return nil, 1
	}

	return &arguments, 0
}

func configParse(
	args []string,
	stderr io.Writer,
	outputs ...*configParseOutput,
) (config, bool) {
	output := &configParseOutput{stdout: io.Discard}
	if len(outputs) > 0 {
		output = outputs[0]
	}

	arguments, code := argumentsParse(chirpUsageText+chirpUsageSuffix,
		append([]string{"chirp"}, args...), output.stdout, stderr)

	output.code = code

	if arguments == nil {
		return config{}, false
	}

	cfg := config{source: arguments.ValueSource, sink: arguments.ValueSink}

	err := configTargetParse(arguments.ValueTarget, &cfg)
	if err != nil {
		output.code = exitUsage

		_, writeErr := fmt.Fprintln(stderr, err)
		if writeErr != nil {
			output.code = 1
		}

		return config{}, false
	}

	return cfg, true
}

func configTargetParse(target string, cfg *config) error {
	handleEnd := strings.IndexByte(target, '@')
	channelStart := strings.IndexByte(target, '/')

	if handleEnd <= 0 || channelStart <= handleEnd+1 ||
		channelStart == len(target)-1 {
		return errors.New(
			"target must be <handle>@<exchange-host>:<exchange-port>/<channel>",
		)
	}

	cfg.handle = proto.Handle(target[:handleEnd])
	cfg.channel = target[channelStart+1:]

	if !proto.HandleValid(cfg.handle) {
		return errors.New("handle must contain only ASCII letters and digits")
	}

	if !proto.RequestValid(cfg.handle, cfg.channel) {
		return errors.New("handle/channel request exceeds protocol limits")
	}

	cfg.channelKey = proto.ChannelKey(cfg.channel)

	address := target[handleEnd+1 : channelStart]

	exchange, err := configExchangeResolve(address)
	if err != nil {
		return err
	}

	cfg.peerex = addrCopy(exchange)

	return nil
}

func configExchangeResolve(address string) (*net.UDPAddr, error) {
	exchange, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		return nil, karma.Describe("address", address).Format(
			err,
			"resolve peer exchange address",
		)
	}

	if exchange.Port == 0 {
		return nil, errors.New("peer exchange address: port must be non-zero")
	}

	if len(exchange.IP) == 0 || exchange.IP.IsUnspecified() {
		return nil, errors.New("peer exchange address: host must be specified")
	}

	return exchange, nil
}
