package main

import (
	"context"
	"encoding/binary"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/reconquest/karma-go"

	"chirik/internal/adpcm"
	"chirik/internal/audio"
	"chirik/internal/proto"
)

const pcmSampleBytes = 2

func (client *client) audioSend(payload []byte) {
	for _, links := range client.links {
		for _, item := range append([]*link(nil), links...) {
			client.audioLinkSend(item, payload)
		}
	}
}

func (client *client) audioLinkSend(item *link, payload []byte) {
	if item.peerex || !item.stateActive() || !item.audioEligible {
		return
	}

	packet, err := item.voice.Seal(proto.Type_Audio, payload)
	if err != nil {
		client.linkRemove(item, karma.Format(err, "encrypt audio").Error())

		return
	}

	err = client.audioPacketSend(item, packet)
	if err != nil {
		client.linkRemove(item, err.Error())

		return
	}

	item.counters.sent.Add(1)
	item.counters.sentBytes.Add(uint64(len(packet)))
	client.counters.sent.Add(1)
	client.counters.sentBytes.Add(uint64(len(packet)))
}

func (client *client) audioPacketSend(item *link, packet []byte) error {
	if item.relay {
		err := client.relaySend(item.handle, packet)
		if err != nil {
			return karma.Format(err, "send relayed audio")
		}

		return nil
	}

	err := datagramSend(client.t.conn, item.addr, packet)
	if err != nil {
		return karma.Format(err, "send audio")
	}

	return nil
}

func (client *client) audioReceive(
	item *link,
	seq uint64,
	payload []byte,
	now time.Time,
) bool {
	if item.peerex || !item.stateActive() || !item.audioEligible ||
		len(payload) != proto.PlainFrame ||
		item.playback == nil {
		return false
	}

	missing := uint64(0)
	if item.lastAudioSeq != 0 {
		missing = seq - item.lastAudioSeq - 1
	}

	state := adpcm.State{
		Predictor: int16(binary.BigEndian.Uint16(payload[0:2])),
		StepIndex: payload[2],
	}
	pcm := adpcm.Decode(state, payload[proto.StateBytes:])

	if missing != 0 {
		item.concealer.Recover(pcm)
	} else {
		item.concealer.Track(pcm)
	}

	pcmBytes := make([]byte, len(pcm)*pcmSampleBytes)
	for index, sample := range pcm {
		binary.LittleEndian.PutUint16(
			pcmBytes[pcmSampleBytes*index:],
			uint16(sample),
		)
	}

	_, err := item.playback.Write(pcmBytes)
	if err != nil {
		client.linkFail(item, karma.Format(err, "write peer playback"))

		return false
	}

	item.lastAudioSeq = seq
	item.lastSeen = now

	return true
}

func (client *client) audioPeerCount() int {
	count := 0

	for _, links := range client.links {
		for _, item := range links {
			if item.stateActive() && item.audioEligible {
				count++
			}
		}
	}

	return count
}

func captureRun(
	ctx context.Context,
	workers *sync.WaitGroup,
	events chan<- error,
	frames chan<- []byte,
	capture io.Reader,
	muted *atomic.Bool,
) {
	defer workers.Done()

	var (
		encoder    adpcm.State
		frameBytes = make([]byte, proto.FrameSamples*pcmSampleBytes)
		pcm        = make([]int16, proto.FrameSamples)
	)

	for {
		_, err := io.ReadFull(capture, frameBytes)
		if err != nil {
			report(ctx, events, karma.Format(err, "capture audio"))

			return
		}

		if muted.Load() {
			clear(frameBytes)
		}

		for index := range proto.FrameSamples {
			pcm[index] = int16(
				binary.LittleEndian.Uint16(frameBytes[pcmSampleBytes*index:]),
			)
		}

		snapshot := encoder
		encoded := adpcm.Encode(&encoder, pcm)
		payload := make([]byte, proto.PlainFrame)
		binary.BigEndian.PutUint16(payload[0:2], uint16(snapshot.Predictor))

		payload[2] = snapshot.StepIndex
		copy(payload[proto.StateBytes:], encoded)

		select {
		case frames <- payload:
		case <-ctx.Done():
			return
		}
	}
}

func audioMonitor(
	ctx context.Context,
	workers *sync.WaitGroup,
	events chan<- error,
	device *audio.Device,
) {
	defer workers.Done()

	err := device.Wait(ctx)
	if err != nil && ctx.Err() == nil {
		report(ctx, events, karma.Format(err, "wait for audio server"))
	}
}

func report(ctx context.Context, events chan<- error, err error) {
	select {
	case events <- err:
	case <-ctx.Done():
	}
}
