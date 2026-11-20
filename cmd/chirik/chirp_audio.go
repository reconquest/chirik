package main

import (
	"context"
	"encoding/binary"
	"io"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/reconquest/karma-go"

	"chirik/internal/adpcm"
	"chirik/internal/audio"
	"chirik/internal/proto"
)

const (
	pcmSampleBytes = 2

	peerCueWriteAttempts     = 2
	peerCueNoteCount         = 3
	peerCueNoteSamples       = proto.SampleRate * 50 / 1000
	peerCueAmplitude         = 5500.0
	peerCueHarmonicAmplitude = 0.25
	peerCueHarmonicRatio     = 2.0
	peerCueSweepMin          = 0.85
	peerCueSweepMax          = 1.15
)

type peerCue byte

const (
	peerCueConnect peerCue = iota
	peerCueDisconnect
	peerCueMute
	peerCueUnmute
)

func (client *client) peerCueQueue(cue peerCue) {
	if client.cueOpen == nil {
		return
	}

	client.pendingCues = append(client.pendingCues, cue)
}

func (client *client) peerCuePlay(cue peerCue) {
	if client.cueOpen == nil {
		return
	}

	data := peerCuePCM(cue)
	for range peerCueWriteAttempts {
		err := client.peerCueWrite(data)
		if err == nil {
			return
		}

		client.peerCueError(err)
	}
}

func (client *client) peerCueWrite(data []byte) error {
	if client.cuePlayback == nil {
		playback, err := client.cueOpen("chirik peer events")
		if err != nil {
			return karma.Format(err, "open peer cue playback")
		}

		client.cuePlayback = playback
	}

	written, err := client.cuePlayback.Write(data)
	if err == nil && written != len(data) {
		err = io.ErrShortWrite
	}

	if err == nil {
		return nil
	}

	client.cuePlayback.Close()

	client.cuePlayback = nil

	return karma.Format(err, "write peer cue playback")
}

func (client *client) peerCueError(err error) {
	if client.logger != nil {
		client.logger.Print("ERROR ", err)
	}
}

func cueRun(
	ctx context.Context,
	workers *sync.WaitGroup,
	client *client,
) {
	defer workers.Done()

	for {
		select {
		case cue := <-client.cues:
			client.peerCuePlay(cue)

		case <-ctx.Done():
			return
		}
	}
}

func peerCuePCM(cue peerCue) []byte {
	data := make([]byte, peerCueNoteCount*peerCueNoteSamples*pcmSampleBytes)
	phase := 0.0

	for note := range peerCueNoteCount {
		frequency := peerCueFrequency(cue, note)

		for index := range peerCueNoteSamples {
			progress := float64(index) / float64(peerCueNoteSamples-1)
			sweep := peerCueSweepMin +
				(peerCueSweepMax-peerCueSweepMin)*progress

			if cue == peerCueDisconnect || cue == peerCueMute {
				sweep = peerCueSweepMax -
					(peerCueSweepMax-peerCueSweepMin)*progress
			}

			phase += 2 * math.Pi * frequency * sweep / proto.SampleRate

			envelope := math.Sin(math.Pi * progress)
			sample := peerCueAmplitude * envelope *
				(math.Sin(phase) + peerCueHarmonicAmplitude*
					math.Sin(peerCueHarmonicRatio*phase))
			offset := (note*peerCueNoteSamples + index) * pcmSampleBytes
			binary.LittleEndian.PutUint16(
				data[offset:],
				uint16(int16(sample)),
			)
		}
	}

	return data
}

func peerCueFrequency(cue peerCue, note int) float64 {
	switch cue {
	case peerCueConnect:
		return [peerCueNoteCount]float64{480, 960, 1440}[note]

	case peerCueDisconnect:
		return [peerCueNoteCount]float64{1440, 720, 240}[note]

	case peerCueMute:
		return [peerCueNoteCount]float64{880, 660, 330}[note]

	case peerCueUnmute:
		return [peerCueNoteCount]float64{330, 660, 880}[note]

	default:
		return 0
	}
}

func (client *client) voiceBroadcast(kind byte, payload []byte) {
	for _, links := range client.links {
		for _, item := range append([]*link(nil), links...) {
			client.voiceLinkSend(item, kind, payload)
		}
	}
}

func (client *client) voiceLinkSend(item *link, kind byte, payload []byte) {
	if !item.voicePeer() {
		return
	}

	packet, err := item.voice.Seal(kind, payload)
	if err != nil {
		client.linkRemove(
			item,
			karma.Format(err, "encrypt peer data").Error(),
		)

		return
	}

	err = client.voicePacketSend(item, packet)
	if err != nil {
		client.linkRemove(item, err.Error())

		return
	}

	item.counters.sent.Add(1)
	item.counters.sentBytes.Add(uint64(len(packet)))
	client.counters.sent.Add(1)
	client.counters.sentBytes.Add(uint64(len(packet)))
}

func (client *client) voicePacketSend(item *link, packet []byte) error {
	if item.relay {
		err := client.relaySend(item.handle, packet)
		if err != nil {
			return karma.Format(err, "send relayed voice peer packet")
		}

		return nil
	}

	err := datagramSend(client.t.conn, item.addr, packet)
	if err != nil {
		return karma.Format(err, "send voice peer packet")
	}

	return nil
}

func (client *client) audioReceive(
	item *link,
	seq uint64,
	payload []byte,
	now time.Time,
) bool {
	if !item.voicePeer() ||
		len(payload) != proto.PlainFrame {
		return false
	}

	if item.playback == nil {
		return true
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

	client.peerPlaybackWrite(item, pcmBytes)

	item.lastAudioSeq = seq
	item.lastSeen = now

	return true
}

func (client *client) peerPlaybackWrite(item *link, data []byte) {
	_, err := item.playback.Write(data)
	if err == nil {
		return
	}

	linkPlaybackClose(item)

	if client.logger != nil {
		client.logger.Print("ERROR ", karma.Format(err, "write peer playback"))
	}
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
