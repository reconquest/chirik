package main

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/reconquest/karma-go"

	"chirik/internal/audio"
	"chirik/internal/proto"
)

type client struct {
	ctx          context.Context
	t            *transport
	cfg          config
	local        *net.UDPAddr
	playbackOpen func(string) (audio.PlaybackWriter, error)
	output       *output
	logger       *log.Logger
	debug        bool
	stderr       io.Writer

	links     map[string][]*link
	seen      map[proto.Handle]struct{}
	discovery *discoveryEngine

	frames   chan []byte
	commands chan byte
	events   chan error
	muted    atomic.Bool
	counters counters
	ready    bool
	readyCh  chan struct{}
	readyOne sync.Once

	endpointRefreshNext    time.Time
	peerexRecoveryRequired bool
	peerexRecoveryStarted  bool
}

type manager = client

const clientTickInterval = 100 * time.Millisecond

const (
	commandInterrupt = byte(0x03)
	commandMute      = byte('m')
	commandQuit      = byte('q')
)

func (client *client) run() error {
	if client.logger == nil {
		client.logger = loggerNew(client.stderr)
	}

	ticker := time.NewTicker(clientTickInterval)

	defer ticker.Stop()

	bitrate := time.NewTicker(time.Second)
	defer bitrate.Stop()

	return client.runLoop(ticker.C, bitrate.C)
}

func (client *client) runLoop(ticks, bitrates <-chan time.Time) error {
	sampledAt := time.Now()

	for {
		err := client.output.writeError()
		if err != nil {
			return err
		}

		stopped, err := client.runEvent(ticks, bitrates, &sampledAt)
		if stopped || err != nil {
			return err
		}
	}
}

func (client *client) runEvent(
	ticks, bitrates <-chan time.Time,
	sampledAt *time.Time,
) (bool, error) {
	select {
	case <-client.ctx.Done():
		return true, nil

	case err := <-client.events:
		return true, err

	case command := <-client.commands:
		return client.commandHandle(command, client.logger), nil

	case frame := <-client.frames:
		client.audioSend(frame)

	case packet := <-client.t.packets:
		client.packetHandle(packet)

	case now := <-ticks:
		return false, client.tick(now)

	case now := <-bitrates:
		client.output.bitrateWrite(
			client.peerBitrates(),
			now.Sub(*sampledAt),
		)

		*sampledAt = now

		client.statsLog(client.logger)
	}

	return false, nil
}

func (client *client) statsLog(logger *log.Logger) {
	if !client.debug {
		return
	}

	logger.Print("DEBUG ", karma.
		Describe("sent", client.counters.sent.Load()).
		Describe("received", client.counters.received.Load()).
		Describe("bad_auth", client.counters.badAuth.Load()).
		Describe("peers", client.audioPeerCount()).
		Format(nil, "packet statistics"),
	)
}

func (client *client) commandHandle(command byte, logger *log.Logger) bool {
	switch command {
	case commandMute:
		muted := !client.muted.Load()
		client.muted.Store(muted)

		if muted {
			client.output.lineWrite("muted")
		} else {
			client.output.lineWrite("unmuted")
		}

		return false

	case commandInterrupt:
		logger.Print("INFO interrupt received")

		return true

	case commandQuit:
		return true

	default:
		return false
	}
}

func (client *client) tick(now time.Time) error {
	err := client.transportError()
	if err != nil {
		return err
	}

	client.endpointRefresh(now)

	for _, links := range client.links {
		for _, item := range append([]*link(nil), links...) {
			linkErr := client.linkTick(item, now)
			if linkErr != nil {
				return linkErr
			}
		}
	}

	return nil
}

func (client *client) transportError() error {
	select {
	case err := <-client.t.errors:
		return karma.Format(err, "read UDP socket")

	default:
		return nil
	}
}

func (client *client) linkTick(item *link, now time.Time) error {
	switch item.state {
	case linkState_KEX:
		return client.linkKEXTick(item, now)

	case linkState_Request:
		return client.linkRequestTick(item, now)

	case linkState_Active:
		return client.linkActiveTick(item, now)

	default:
		return nil
	}
}

func (client *client) linkKEXTick(item *link, now time.Time) error {
	if now.After(item.kexDeadline) {
		return client.linkTickError(item, errors.New("key exchange timed out"))
	}

	if now.Before(item.kexNext) {
		return nil
	}

	err := client.linkKEXSend(item, now)
	if err != nil {
		return client.linkTickError(item, err)
	}

	return nil
}

func (client *client) linkRequestTick(item *link, now time.Time) error {
	if requestSendDue(item, now) {
		err := client.linkRequestSend(item, now)
		if err != nil {
			return client.linkTickError(item, err)
		}
	}

	responseExpired := !item.responseDeadline.IsZero() &&
		now.After(item.responseDeadline) && !item.responseReceived
	if responseExpired {
		return client.linkTickError(
			item,
			errors.New("peer-list response timed out"),
		)
	}

	return nil
}

func (client *client) linkActiveTick(item *link, now time.Time) error {
	if requestSendDue(item, now) {
		err := client.linkRequestSend(item, now)
		if err != nil {
			return client.linkTickError(item, err)
		}
	}

	if !item.peerex &&
		now.Sub(item.lastSeen) > client.discoveryEnsure().policy.ttl {
		client.linkRemove(item, "expired")
	}

	return nil
}

func (client *client) linkTickError(item *link, err error) error {
	if item.bootstrap && !client.ready {
		return err
	}

	client.linkRemove(item, err.Error())

	return nil
}

func requestSendDue(item *link, now time.Time) bool {
	if item.requestAttempts >= proto.RequestAttempts ||
		now.Before(item.requestNext) {
		return false
	}

	if item.state == linkState_Active {
		return !item.peerex && item.initiated && !item.responseReceived
	}

	return !item.peerex || item.initiated
}

func (client *client) markReady(item *link) {
	if client.ready || !item.bootstrap {
		return
	}

	client.ready = true
	client.readyOne.Do(func() { close(client.readyCh) })
	client.output.lineWrite("exchange handshake complete")

	if client.audioPeerCount() == 0 {
		client.output.lineWrite("no voice peers connected; waiting for peers")
	}
}

func (client *client) close() {
	for _, links := range client.links {
		for _, item := range links {
			if item.playback != nil {
				item.playback.Close()
			}
		}
	}

	client.links = make(map[string][]*link)
}
