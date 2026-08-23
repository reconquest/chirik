package audio

import "testing"

func TestConcealerRecoverCrossfadesFromLastSample(t *testing.T) {
	concealer := Concealer{}
	concealer.Track([]int16{12000})

	frame := make([]int16, 480)
	for i := range frame {
		frame[i] = -12000
	}
	concealer.Recover(frame)

	if frame[0] != 11800 {
		t.Fatalf("first sample = %d, want 11800", frame[0])
	}

	if frame[concealRecoverySamples-1] != -12000 {
		t.Fatalf(
			"fade terminal sample = %d, want -12000",
			frame[concealRecoverySamples-1],
		)
	}

	if delta := int(frame[0]) - 12000; delta < -200 || delta > 200 {
		t.Fatalf("recovery boundary delta = %d", delta)
	}
}
