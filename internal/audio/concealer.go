package audio

const concealRecoverySamples = 120

type Concealer struct {
	last int16
}

func (c *Concealer) Track(frame []int16) {
	if len(frame) != 0 {
		c.last = frame[len(frame)-1]
	}
}

func (c *Concealer) Recover(frame []int16) {
	count := min(len(frame), concealRecoverySamples)
	start := int32(c.last)
	for i := range count {
		progress := int32(i + 1)
		frame[i] = int16(
			(start*int32(count-i-1) + int32(frame[i])*progress) /
				int32(count),
		)
	}
	c.Track(frame)
}
