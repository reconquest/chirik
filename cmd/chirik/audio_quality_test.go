package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"chirik/internal/proto"
)

type audioQualityPlayback struct {
	bytes.Buffer
}

func (*audioQualityPlayback) Close() {}

func TestAudioQuality(t *testing.T) {
	if proto.SampleRate != 48000 || proto.Channels != 1 {
		t.Fatal("audio quality fixture requires 48000 Hz mono PCM")
	}

	reference := audioQualitySignal()
	received := audioQualityRoundTrip(t, reference)
	if len(received) != len(reference) {
		t.Fatalf("received %d bytes, want %d", len(received), len(reference))
	}

	var signal, noise, energy, peak float64
	clipped := 0
	for offset := 0; offset < len(reference); offset += pcmSampleBytes {
		original := float64(int16(binary.LittleEndian.Uint16(reference[offset:])))
		sample := int16(binary.LittleEndian.Uint16(received[offset:]))
		value := float64(sample)
		difference := original - value
		signal += original * original
		noise += difference * difference
		energy += value * value
		peak = math.Max(peak, math.Abs(value))
		if sample == -32768 || sample == 32767 {
			clipped++
		}
	}

	samples := len(reference) / pcmSampleBytes
	snr := 10 * math.Log10(signal/noise)
	peakDBFS := 20 * math.Log10(peak/32768)
	rmsDBFS := 20 * math.Log10(math.Sqrt(energy/float64(samples))/32768)
	t.Logf(
		"synthetic full-pipeline fidelity only: SNR=%.2f dB, "+
			"received peak=%.2f dBFS, RMS=%.2f dBFS, "+
			"clipped=%d, duration=%.2f s",
		snr, peakDBFS, rmsDBFS, clipped,
		float64(samples)/proto.SampleRate,
	)
	if math.IsNaN(snr) || math.IsInf(snr, 0) || snr < 20 {
		t.Errorf("SNR = %v dB, want finite and >= 20 dB", snr)
	}
	if clipped != 0 {
		t.Errorf("clipped output samples = %d, want 0", clipped)
	}
	if energy == 0 {
		t.Error("received output is silent")
	}

	if directory := os.Getenv("CHIRIK_AUDIO_TEST_DIR"); directory != "" {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatalf("create audio artifact directory: %v", err)
		}
		audioQualityWAV(t, filepath.Join(directory, "reference.wav"), reference)
		audioQualityWAV(t, filepath.Join(directory, "received.wav"), received)
	}
}

func audioQualitySignal() []byte {
	const (
		samples = 4 * proto.SampleRate
		silence = proto.SampleRate / 10
		ramp    = proto.SampleRate / 5
	)
	pcm := make([]byte, samples*pcmSampleBytes)
	for index := silence; index < samples-silence; index++ {
		progress := math.Min(1, float64(index-silence)/ramp)
		progress = math.Min(progress, float64(samples-silence-1-index)/ramp)
		envelope := 0.5 - 0.5*math.Cos(math.Pi*progress)
		phase := 2 * math.Pi * float64(index-silence) / proto.SampleRate
		value := 0.50*math.Sin(330*phase) + 0.25*math.Sin(770*phase) +
			0.15*math.Sin(1430*phase) + 0.10*math.Sin(2860*phase)
		sample := int16(math.Round(0.65 * 32767 * envelope * value))
		binary.LittleEndian.PutUint16(pcm[index*pcmSampleBytes:], uint16(sample))
	}

	return pcm
}

func audioQualityRoundTrip(t *testing.T, reference []byte) []byte {
	t.Helper()

	frameBytes := proto.FrameSamples * pcmSampleBytes
	if len(reference)%frameBytes != 0 {
		t.Fatal("reference does not contain whole PCM frames")
	}
	sender, receiver := sessionTestPair(t, 41)
	playback := &audioQualityPlayback{}
	defer playback.Close()
	item := &link{
		state:         linkState_Active,
		audioEligible: true,
		playback:      playback,
	}
	var client client

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	frames := make(chan []byte)
	events := make(chan error, 1)
	done := make(chan struct{})
	var workers sync.WaitGroup
	var muted atomic.Bool
	workers.Add(1)
	go func() {
		defer close(done)
		defer close(frames)
		captureRun(ctx, &workers, events, frames, bytes.NewReader(reference), &muted)
	}()
	defer func() {
		cancel()
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		select {
		case <-done:
			workers.Wait()
		case <-timer.C:
			t.Error("capture goroutine did not stop")
		}
	}()

	frameCount := 0
	for {
		select {
		case <-ctx.Done():
			t.Fatalf("capture timed out after %d frames", frameCount)
		case payload, ok := <-frames:
			if !ok {
				select {
				case err := <-events:
					if !errors.Is(err, io.EOF) {
						t.Fatalf("capture: %v", err)
					}
				default:
					t.Fatal("capture ended without EOF")
				}
				if frameCount != len(reference)/frameBytes {
					t.Fatalf("captured %d frames, want %d",
						frameCount, len(reference)/frameBytes)
				}
				return playback.Bytes()
			}
			frameCount++
			if frameCount > len(reference)/frameBytes {
				t.Fatal("capture produced excess frames")
			}
			if len(payload) != proto.PlainFrame {
				t.Fatalf("frame %d: payload length = %d", frameCount, len(payload))
			}
			if payload[2] > 88 {
				t.Fatalf("frame %d: invalid ADPCM step index %d", frameCount, payload[2])
			}
			packet, err := sender.Seal(proto.Type_Audio, payload)
			if err != nil {
				t.Fatalf("frame %d: seal audio: %v", frameCount, err)
			}
			if len(packet) != proto.AudioPacketBytes || packet[0] != proto.Type_Audio {
				t.Fatalf("frame %d: invalid audio envelope", frameCount)
			}
			kind, sequence, opened, err := receiver.Open(packet)
			if err != nil {
				t.Fatalf("frame %d: open audio: %v", frameCount, err)
			}
			if kind != proto.Type_Audio || sequence != uint64(frameCount) ||
				len(opened) != proto.PlainFrame || !bytes.Equal(opened, payload) {
				t.Fatalf("frame %d: invalid decrypted audio frame", frameCount)
			}
			before := playback.Len()
			now := time.Unix(0, 0).Add(time.Duration(frameCount) *
				time.Second * proto.FrameSamples / proto.SampleRate)
			if !client.audioReceive(item, sequence, opened, now) {
				t.Fatalf("frame %d: audioReceive rejected frame", frameCount)
			}
			if playback.Len()-before != frameBytes {
				t.Fatalf("frame %d: playback wrote %d bytes, want %d",
					frameCount, playback.Len()-before, frameBytes)
			}
		}
	}
}

func audioQualityWAV(t *testing.T, path string, pcm []byte) {
	t.Helper()

	wav := make([]byte, 44+len(pcm))
	copy(wav[0:4], "RIFF")
	binary.LittleEndian.PutUint32(wav[4:8], uint32(len(wav)-8))
	copy(wav[8:16], "WAVEfmt ")
	binary.LittleEndian.PutUint32(wav[16:20], 16)
	binary.LittleEndian.PutUint16(wav[20:22], 1)
	binary.LittleEndian.PutUint16(wav[22:24], proto.Channels)
	binary.LittleEndian.PutUint32(wav[24:28], proto.SampleRate)
	binary.LittleEndian.PutUint32(wav[28:32], proto.SampleRate*pcmSampleBytes)
	binary.LittleEndian.PutUint16(wav[32:34], pcmSampleBytes)
	binary.LittleEndian.PutUint16(wav[34:36], 16)
	copy(wav[36:40], "data")
	binary.LittleEndian.PutUint32(wav[40:44], uint32(len(pcm)))
	copy(wav[44:], pcm)
	if err := os.WriteFile(path, wav, 0o644); err != nil {
		t.Fatalf("write audio artifact %s: %v", path, err)
	}
}
