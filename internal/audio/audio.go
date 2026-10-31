package audio

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/reconquest/karma-go"

	"chirik/internal/proto"
	"chirik/internal/pulse"
	pulseproto "chirik/internal/pulse/proto"
)

const (
	pcmSampleBytes = 2

	bufferChunks        = 32
	playbackFadeSamples = 120
)

type Device struct {
	Capture io.Reader

	client        *pulse.Client
	captureBuffer *pcmBuffer
	record        *pulse.RecordStream
	sink          *pulse.Sink

	mu        sync.Mutex
	playbacks map[*Playback]struct{}
	closed    bool
	close     sync.Once
}

type PlaybackWriter interface {
	io.Writer
	Close()
}

type Playback struct {
	device *Device
	buffer *pcmBuffer
	stream *pulse.PlaybackStream
	close  sync.Once
}

type pcmBuffer struct {
	chunks  chan []byte
	done    chan struct{}
	pending []byte
	silence bool
	close   sync.Once

	playbackLast         int16
	playbackUnderflow    bool
	playbackFadeStart    int16
	playbackFadePosition int
	playbackRecoverStart int16
	playbackRecoverPos   int
}

func Check(sourceID, sinkID string) error {
	client, err := pulse.NewClient(
		pulse.ClientApplicationName("chirik"),
		pulse.ClientTimeout(time.Second),
	)
	if err != nil {
		return karma.Format(err, "connect to PipeWire Pulse server")
	}
	defer client.Close()

	_, _, err = devicesResolve(client, sourceID, sinkID)

	return err
}

func Open(sourceID, sinkID string) (*Device, error) {
	client, err := pulse.NewClient(
		pulse.ClientApplicationName("chirik"),
		pulse.ClientTimeout(time.Second),
	)
	if err != nil {
		return nil, karma.Format(err, "connect to PipeWire Pulse server")
	}

	source, sink, err := devicesResolve(client, sourceID, sinkID)
	if err != nil {
		client.Close()

		return nil, err
	}

	captureBuffer := pcmBufferNew(false)
	recordOptions := []pulse.RecordOption{
		pulse.RecordSampleRate(proto.SampleRate),
		pulse.RecordChannels(pulseproto.ChannelMap{pulseproto.ChannelMono}),
		pulse.RecordBufferFragmentSize(proto.FrameSamples * pcmSampleBytes),
		pulse.RecordMediaName("chirik capture"),
	}

	if source != nil {
		recordOptions = append(recordOptions, pulse.RecordSource(source))
	}

	record, err := client.NewRecord(
		pulse.NewWriter(captureBuffer, pulseproto.FormatInt16LE),
		recordOptions...,
	)
	if err != nil {
		client.Close()
		captureBuffer.Close()

		return nil, karma.Format(err, "create capture stream")
	}

	record.Start()

	return &Device{
		Capture:       captureBuffer,
		client:        client,
		captureBuffer: captureBuffer,
		record:        record,
		sink:          sink,
		playbacks:     make(map[*Playback]struct{}),
	}, nil
}

func (device *Device) PlaybackOpen(mediaName string) (*Playback, error) {
	buffer := pcmBufferNew(true)
	options := []pulse.PlaybackOption{
		pulse.PlaybackSampleRate(proto.SampleRate),
		pulse.PlaybackChannels(pulseproto.ChannelMap{pulseproto.ChannelMono}),
		pulse.PlaybackBufferSize(proto.FrameSamples),
		pulse.PlaybackMediaName(mediaName),
	}

	if device.sink != nil {
		options = append(options, pulse.PlaybackSink(device.sink))
	}

	device.mu.Lock()
	defer device.mu.Unlock()

	if device.closed {
		buffer.Close()

		return nil, errors.New("audio device closed")
	}

	stream, err := device.client.NewPlayback(
		pulse.NewReader(buffer, pulseproto.FormatInt16LE),
		options...,
	)
	if err != nil {
		buffer.Close()

		return nil, karma.Format(err, "create playback stream")
	}

	stream.Start()

	playback := &Playback{
		device: device,
		buffer: buffer,
		stream: stream,
	}

	device.playbacks[playback] = struct{}{}

	return playback, nil
}

func (device *Device) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return nil

	case <-device.client.Done():
		err := device.client.Error()
		if err != nil {
			return karma.Format(err, "read audio connection")
		}

		return errors.New("audio connection closed")
	}
}

func (device *Device) Close() {
	device.close.Do(func() {
		device.mu.Lock()

		device.closed = true

		playbacks := make([]*Playback, 0, len(device.playbacks))

		for playback := range device.playbacks {
			playbacks = append(playbacks, playback)
		}

		device.mu.Unlock()

		for _, playback := range playbacks {
			playback.Close()
		}

		device.record.Close()
		device.captureBuffer.Close()
		device.client.Close()
	})
}

func (playback *Playback) Write(
	data []byte,
) (int, error) {
	return playback.buffer.Write(data)
}

func (playback *Playback) Close() {
	playback.close.Do(func() {
		playback.stream.Close()
		playback.buffer.Close()

		playback.device.mu.Lock()
		delete(playback.device.playbacks, playback)
		playback.device.mu.Unlock()
	})
}

func devicesResolve(
	client *pulse.Client,
	sourceID string,
	sinkID string,
) (*pulse.Source, *pulse.Sink, error) {
	var (
		source *pulse.Source
		sink   *pulse.Sink
		err    error
	)

	if sourceID != "" {
		source, err = client.SourceByID(sourceID)
		if err != nil {
			return nil, nil, karma.Describe("source_id", sourceID).
				Format(err, "find source")
		}
	}

	if sinkID != "" {
		sink, err = client.SinkByID(sinkID)
		if err != nil {
			return nil, nil, karma.Describe("sink_id", sinkID).
				Format(err, "find sink")
		}
	}

	return source, sink, nil
}

func pcmBufferNew(silence bool) *pcmBuffer {
	return &pcmBuffer{
		chunks:  make(chan []byte, bufferChunks),
		done:    make(chan struct{}),
		silence: silence,
	}
}

func (buffer *pcmBuffer) Read(data []byte) (int, error) {
	if buffer.silence {
		return buffer.readPlayback(data)
	}

	return buffer.readCapture(data)
}

func (buffer *pcmBuffer) Write(data []byte) (int, error) {
	select {
	case <-buffer.done:
		return 0, errors.New("audio buffer closed")

	default:
	}

	chunk := append([]byte(nil), data...)
	select {
	case buffer.chunks <- chunk:
		return len(data), nil

	default:
	}

	select {
	case <-buffer.chunks:
	default:
	}

	select {
	case buffer.chunks <- chunk:
		return len(data), nil

	case <-buffer.done:
		return 0, errors.New("audio buffer closed")
	}
}

func (buffer *pcmBuffer) Close() {
	buffer.close.Do(func() { close(buffer.done) })
}

func (buffer *pcmBuffer) readCapture(data []byte) (int, error) {
	for len(buffer.pending) == 0 {
		select {
		case buffer.pending = <-buffer.chunks:
		case <-buffer.done:
			return 0, io.EOF
		}
	}

	n := copy(data, buffer.pending)

	buffer.pending = buffer.pending[n:]

	return n, nil
}

func (buffer *pcmBuffer) readPlayback(data []byte) (int, error) {
	clear(data)

	written := 0
	for written < len(data) {
		if len(buffer.pending) != 0 {
			start := written
			n := copy(data[written:], buffer.pending)

			buffer.pending = buffer.pending[n:]

			written += n
			buffer.playbackSamplesApply(data[start:written])

			continue
		}

		select {
		case buffer.pending = <-buffer.chunks:
		case <-buffer.done:
			if written == 0 {
				return 0, io.EOF
			}

			return written, nil

		default:
			buffer.playbackSilenceFill(data[written:])

			return len(data), nil
		}
	}

	return written, nil
}

func (buffer *pcmBuffer) playbackSamplesApply(data []byte) {
	if buffer.playbackUnderflow {
		buffer.playbackRecoverStart = buffer.playbackLast
		buffer.playbackRecoverPos = 0
		buffer.playbackUnderflow = false
	}

	for sampleIndex := range len(data) / pcmSampleBytes {
		sample := int16(
			binary.LittleEndian.Uint16(data[pcmSampleBytes*sampleIndex:]),
		)

		if buffer.playbackRecoverPos < playbackFadeSamples {
			progress := buffer.playbackRecoverPos + 1

			previous := int32(buffer.playbackRecoverStart) *
				int32(playbackFadeSamples-progress)
			current := int32(sample) * int32(progress)

			sample = int16((previous + current) / playbackFadeSamples)
			buffer.playbackRecoverPos++
		}

		binary.LittleEndian.PutUint16(
			data[pcmSampleBytes*sampleIndex:],
			uint16(sample),
		)

		buffer.playbackLast = sample
	}
}

func (buffer *pcmBuffer) playbackSilenceFill(data []byte) {
	clear(data)

	if !buffer.playbackUnderflow {
		buffer.playbackUnderflow = true
		buffer.playbackFadeStart = buffer.playbackLast
		buffer.playbackFadePosition = 0
	}

	for sampleIndex := range len(data) / pcmSampleBytes {
		if buffer.playbackFadePosition >= playbackFadeSamples {
			buffer.playbackLast = 0

			continue
		}

		remaining := playbackFadeSamples - buffer.playbackFadePosition - 1
		sample := int16(
			int32(
				buffer.playbackFadeStart,
			) * int32(
				remaining,
			) / playbackFadeSamples,
		)
		binary.LittleEndian.PutUint16(
			data[pcmSampleBytes*sampleIndex:],
			uint16(sample),
		)

		buffer.playbackLast = sample
		buffer.playbackFadePosition++
	}
}
