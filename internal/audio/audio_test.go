package audio

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"testing"
	"time"

	"chirik/internal/proto"
)

func TestPCMBufferCapture(t *testing.T) {
	buffer := pcmBufferNew(false)
	defer buffer.Close()

	input := []byte{1, 2, 3, 4, 5}
	if n, err := buffer.Write(input); err != nil || n != len(input) {
		t.Fatalf("write = %d, %v", n, err)
	}

	output := make([]byte, len(input))
	if _, err := io.ReadFull(buffer, output); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(output, input) {
		t.Fatalf("capture = %v, want %v", output, input)
	}
}

func TestPCMBufferPlaybackFadesUnderflowAndRecovery(t *testing.T) {
	buffer := pcmBufferNew(true)
	defer buffer.Close()

	silence := make([]byte, 2*proto.FrameSamples)
	if n, err := buffer.Read(silence); err != nil || n != len(silence) {
		t.Fatalf("silence read = %d, %v", n, err)
	}

	if !bytes.Equal(silence, make([]byte, len(silence))) {
		t.Fatal("initial underflow is not silent")
	}

	positive := pcmTestBytes(12000)
	if _, err := buffer.Write(positive); err != nil {
		t.Fatal(err)
	}

	recovered := make([]byte, len(positive))
	if n, err := buffer.Read(recovered); err != nil || n != len(recovered) {
		t.Fatalf("recovery read = %d, %v", n, err)
	}

	recoveredPCM := pcmTestSamples(recovered)
	if recoveredPCM[0] != 100 || recoveredPCM[playbackFadeSamples-1] != 12000 {
		t.Fatalf(
			"recovery fade = %d..%d",
			recoveredPCM[0], recoveredPCM[playbackFadeSamples-1],
		)
	}

	underflow := make([]byte, len(positive))
	if n, err := buffer.Read(underflow); err != nil || n != len(underflow) {
		t.Fatalf("underflow read = %d, %v", n, err)
	}

	underflowPCM := pcmTestSamples(underflow)
	if underflowPCM[0] != 11900 || underflowPCM[playbackFadeSamples-1] != 0 {
		t.Fatalf(
			"underflow fade = %d..%d",
			underflowPCM[0], underflowPCM[playbackFadeSamples-1],
		)
	}

	negative := pcmTestBytes(-12000)
	if _, err := buffer.Write(negative); err != nil {
		t.Fatal(err)
	}

	if n, err := buffer.Read(recovered); err != nil || n != len(recovered) {
		t.Fatalf("second recovery read = %d, %v", n, err)
	}

	recoveredPCM = pcmTestSamples(recovered)
	if recoveredPCM[0] != -100 || recoveredPCM[playbackFadeSamples-1] != -12000 {
		t.Fatalf(
			"second recovery fade = %d..%d",
			recoveredPCM[0], recoveredPCM[playbackFadeSamples-1],
		)
	}
}

func TestPCMBufferClose(t *testing.T) {
	buffer := pcmBufferNew(false)
	buffer.Close()

	if _, err := buffer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("read error = %v, want EOF", err)
	}

	if _, err := buffer.Write([]byte{1}); err == nil {
		t.Fatal("write succeeded after close")
	}
}

func TestDeviceIntegration(t *testing.T) {
	if os.Getenv("CHIRIK_AUDIO_INTEGRATION") == "" {
		t.Skip("set CHIRIK_AUDIO_INTEGRATION=1 to test the live PipeWire Pulse server")
	}

	if err := Check("", ""); err != nil {
		t.Fatal(err)
	}

	device, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()

	captured := make(chan error, 1)
	go func() {
		frame := make([]byte, 960)
		_, err := io.ReadFull(device.Capture, frame)
		captured <- err
	}()

	playback, err := device.PlaybackOpen("chirik test playback")
	if err != nil {
		t.Fatal(err)
	}
	defer playback.Close()

	if _, err := playback.Write(make([]byte, 960)); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-captured:
		if err != nil {
			t.Fatal(err)
		}

	case <-time.After(2 * time.Second):
		t.Fatal("capture timed out")
	}
}

func pcmTestBytes(value int16) []byte {
	data := make([]byte, 2*proto.FrameSamples)
	for i := range proto.FrameSamples {
		binary.LittleEndian.PutUint16(data[2*i:], uint16(value))
	}

	return data
}

func pcmTestSamples(data []byte) []int16 {
	samples := make([]int16, len(data)/2)
	for i := range len(samples) {
		samples[i] = int16(binary.LittleEndian.Uint16(data[2*i:]))
	}

	return samples
}
