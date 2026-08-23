package adpcm

import (
	"math"
	"reflect"
	"testing"
)

const (
	testSampleRate   = 48000
	testFrameSamples = 480
)

func TestRoundTripSNR(t *testing.T) {
	pcm := sinePCM(testSampleRate, 440, -12)
	decoded := make([]int16, 0, len(pcm))
	var encoder State

	for offset := 0; offset < len(pcm); offset += testFrameSamples {
		state := encoder
		data := Encode(&encoder, pcm[offset:offset+testFrameSamples])
		decoded = append(decoded, Decode(state, data)...)
	}

	snr := signalNoiseRatio(pcm, decoded)
	if snr <= 25 {
		t.Fatalf("SNR = %.2f dB, want > 25 dB", snr)
	}
}

func TestEncodeDeterminism(t *testing.T) {
	pcm := sinePCM(testFrameSamples, 731, -8)
	firstState := State{Predictor: -1234, StepIndex: 17}
	secondState := firstState

	first := Encode(&firstState, pcm)
	second := Encode(&secondState, pcm)
	if !reflect.DeepEqual(first, second) {
		t.Fatal("encoded output differs")
	}

	if firstState != secondState {
		t.Fatalf("final state differs: %+v != %+v", firstState, secondState)
	}
}

func TestFrameStateIndependence(t *testing.T) {
	pcm := sinePCM(4*testFrameSamples, 997, -10)
	var (
		encoder    State
		continuous State
	)

	for offset := 0; offset < len(pcm); offset += testFrameSamples {
		snapshot := encoder
		data := Encode(&encoder, pcm[offset:offset+testFrameSamples])
		independent := Decode(snapshot, data)
		streamed := make([]int16, testFrameSamples)
		decode(&continuous, data, streamed)
		if !reflect.DeepEqual(independent, streamed) {
			t.Fatalf("frame %d differs", offset/testFrameSamples)
		}

		if continuous != encoder {
			t.Fatalf("frame %d state differs: decoder=%+v encoder=%+v", offset/testFrameSamples, continuous, encoder)
		}
	}
}

func sinePCM(samples int, frequency float64, decibels float64) []int16 {
	amplitude := 32767 * math.Pow(10, decibels/20)
	pcm := make([]int16, samples)
	for i := range samples {
		phase := 2 * math.Pi * frequency * float64(i) / testSampleRate
		pcm[i] = int16(math.Round(amplitude * math.Sin(phase)))
	}

	return pcm
}

func signalNoiseRatio(original []int16, decoded []int16) float64 {
	var (
		signal float64
		noise  float64
	)

	for i := range original {
		sample := float64(original[i])
		errorValue := sample - float64(decoded[i])
		signal += sample * sample
		noise += errorValue * errorValue
	}

	return 10 * math.Log10(signal/noise)
}
