package audio

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"chirik/internal/proto"
	"chirik/internal/pulse"
	pulseproto "chirik/internal/pulse/proto"
)

const (
	bufferChunks        = 32
	playbackFadeSamples = 120
)

type Device struct {
	Capture io.Reader

	client  *pulse.Client
	capture *pcmBuffer
	record  *pulse.RecordStream
	sink    *pulse.Sink

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
		return fmt.Errorf("connect to PipeWire Pulse server: %w", err)
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
		return nil, fmt.Errorf("connect to PipeWire Pulse server: %w", err)
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
		pulse.RecordBufferFragmentSize(proto.FrameSamples * 2),
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
		return nil, fmt.Errorf("create capture stream: %w", err)
	}
	record.Start()

	return &Device{
		Capture:   captureBuffer,
		client:    client,
		capture:   captureBuffer,
		record:    record,
		sink:      sink,
		playbacks: make(map[*Playback]struct{}),
	}, nil
}

func (d *Device) PlaybackOpen(mediaName string) (*Playback, error) {
	buffer := pcmBufferNew(true)
	options := []pulse.PlaybackOption{
		pulse.PlaybackSampleRate(proto.SampleRate),
		pulse.PlaybackChannels(pulseproto.ChannelMap{pulseproto.ChannelMono}),
		pulse.PlaybackBufferSize(proto.FrameSamples),
		pulse.PlaybackMediaName(mediaName),
	}
	if d.sink != nil {
		options = append(options, pulse.PlaybackSink(d.sink))
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		buffer.Close()
		return nil, errors.New("audio device closed")
	}

	stream, err := d.client.NewPlayback(
		pulse.NewReader(buffer, pulseproto.FormatInt16LE),
		options...,
	)
	if err != nil {
		buffer.Close()
		return nil, fmt.Errorf("create playback stream: %w", err)
	}
	stream.Start()

	playback := &Playback{
		device: d,
		buffer: buffer,
		stream: stream,
	}
	d.playbacks[playback] = struct{}{}

	return playback, nil
}

func (d *Device) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return nil

	case <-d.client.Done():
		if err := d.client.Error(); err != nil {
			return err
		}

		return errors.New("audio connection closed")
	}
}

func (d *Device) Close() {
	d.close.Do(func() {
		d.mu.Lock()
		d.closed = true
		playbacks := make([]*Playback, 0, len(d.playbacks))
		for playback := range d.playbacks {
			playbacks = append(playbacks, playback)
		}
		d.mu.Unlock()

		for _, playback := range playbacks {
			playback.Close()
		}

		d.record.Close()
		d.capture.Close()
		d.client.Close()
	})
}

func (p *Playback) Write(data []byte) (int, error) { return p.buffer.Write(data) }

func (p *Playback) Close() {
	p.close.Do(func() {
		p.stream.Close()
		p.buffer.Close()

		p.device.mu.Lock()
		delete(p.device.playbacks, p)
		p.device.mu.Unlock()
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
			return nil, nil, fmt.Errorf("find source %q: %w", sourceID, err)
		}
	}

	if sinkID != "" {
		sink, err = client.SinkByID(sinkID)
		if err != nil {
			return nil, nil, fmt.Errorf("find sink %q: %w", sinkID, err)
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

func (b *pcmBuffer) Read(data []byte) (int, error) {
	if b.silence {
		return b.readPlayback(data)
	}

	return b.readCapture(data)
}

func (b *pcmBuffer) Write(data []byte) (int, error) {
	select {
	case <-b.done:
		return 0, errors.New("audio buffer closed")
	default:
	}

	chunk := append([]byte(nil), data...)
	select {
	case b.chunks <- chunk:
		return len(data), nil
	default:
	}

	select {
	case <-b.chunks:
	default:
	}

	select {
	case b.chunks <- chunk:
		return len(data), nil
	case <-b.done:
		return 0, errors.New("audio buffer closed")
	}
}

func (b *pcmBuffer) Close() {
	b.close.Do(func() { close(b.done) })
}

func (b *pcmBuffer) readCapture(data []byte) (int, error) {
	for len(b.pending) == 0 {
		select {
		case b.pending = <-b.chunks:
		case <-b.done:
			return 0, io.EOF
		}
	}

	n := copy(data, b.pending)
	b.pending = b.pending[n:]
	return n, nil
}

func (b *pcmBuffer) readPlayback(data []byte) (int, error) {
	clear(data)
	written := 0
	for written < len(data) {
		if len(b.pending) != 0 {
			start := written
			n := copy(data[written:], b.pending)
			b.pending = b.pending[n:]
			written += n
			b.playbackSamplesApply(data[start:written])
			continue
		}

		select {
		case b.pending = <-b.chunks:
		case <-b.done:
			if written == 0 {
				return 0, io.EOF
			}

			return written, nil
		default:
			b.playbackSilenceFill(data[written:])
			return len(data), nil
		}
	}

	return written, nil
}

func (b *pcmBuffer) playbackSamplesApply(data []byte) {
	if b.playbackUnderflow {
		b.playbackRecoverStart = b.playbackLast
		b.playbackRecoverPos = 0
		b.playbackUnderflow = false
	}

	for i := range len(data) / 2 {
		sample := int16(binary.LittleEndian.Uint16(data[2*i:]))
		if b.playbackRecoverPos < playbackFadeSamples {
			progress := b.playbackRecoverPos + 1
			sample = int16(
				(int32(b.playbackRecoverStart)*int32(playbackFadeSamples-progress) +
					int32(sample)*int32(progress)) /
					playbackFadeSamples,
			)
			b.playbackRecoverPos++
		}

		binary.LittleEndian.PutUint16(data[2*i:], uint16(sample))
		b.playbackLast = sample
	}
}

func (b *pcmBuffer) playbackSilenceFill(data []byte) {
	clear(data)
	if !b.playbackUnderflow {
		b.playbackUnderflow = true
		b.playbackFadeStart = b.playbackLast
		b.playbackFadePosition = 0
	}

	for i := range len(data) / 2 {
		if b.playbackFadePosition >= playbackFadeSamples {
			b.playbackLast = 0
			continue
		}

		remaining := playbackFadeSamples - b.playbackFadePosition - 1
		sample := int16(
			int32(b.playbackFadeStart) * int32(remaining) / playbackFadeSamples,
		)
		binary.LittleEndian.PutUint16(data[2*i:], uint16(sample))
		b.playbackLast = sample
		b.playbackFadePosition++
	}
}
