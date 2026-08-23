package adpcm

type State struct {
	Predictor int16
	StepIndex uint8
}

var stepTable = [...]int{
	7, 8, 9, 10, 11, 12, 13, 14, 16, 17,
	19, 21, 23, 25, 28, 31, 34, 37, 41, 45,
	50, 55, 60, 66, 73, 80, 88, 97, 107, 118,
	130, 143, 157, 173, 190, 209, 230, 253, 279, 307,
	337, 371, 408, 449, 494, 544, 598, 658, 724, 796,
	876, 963, 1060, 1166, 1282, 1411, 1552, 1707, 1878, 2066,
	2272, 2499, 2749, 3024, 3327, 3660, 4026, 4428, 4871, 5358,
	5894, 6484, 7132, 7845, 8630, 9493, 10442, 11487, 12635, 13899,
	15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767,
}

var indexTable = [...]int{
	-1, -1, -1, -1, 2, 4, 6, 8,
	-1, -1, -1, -1, 2, 4, 6, 8,
}

func Encode(s *State, pcm []int16) []byte {
	encoded := make([]byte, (len(pcm)+1)/2)
	for i, sample := range pcm {
		nibble := encodeSample(s, sample)
		if i&1 == 0 {
			encoded[i/2] = nibble
		} else {
			encoded[i/2] |= nibble << 4
		}
	}

	return encoded
}

func Decode(s State, data []byte) []int16 {
	pcm := make([]int16, len(data)*2)
	decode(&s, data, pcm)

	return pcm
}

func encodeSample(s *State, sample int16) byte {
	index := clampIndex(int(s.StepIndex))
	predictor := int(s.Predictor)
	step := stepTable[index]
	difference := int(sample) - predictor
	nibble := byte(0)
	if difference < 0 {
		nibble = 8
		difference = -difference
	}

	delta := step >> 3
	if difference >= step {
		nibble |= 4
		difference -= step
		delta += step
	}

	step >>= 1
	if difference >= step {
		nibble |= 2
		difference -= step
		delta += step
	}

	step >>= 1
	if difference >= step {
		nibble |= 1
		delta += step
	}

	if nibble&8 != 0 {
		predictor -= delta
	} else {
		predictor += delta
	}

	predictor = clampPredictor(predictor)
	index = clampIndex(index + indexTable[nibble])
	s.Predictor = int16(predictor)
	s.StepIndex = uint8(index)

	return nibble
}

func decode(s *State, data []byte, pcm []int16) {
	index := clampIndex(int(s.StepIndex))
	predictor := int(s.Predictor)
	for i := range len(pcm) {
		nibble := data[i/2] >> (4 * (i & 1)) & 0x0f
		step := stepTable[index]
		delta := step >> 3
		if nibble&4 != 0 {
			delta += step
		}

		if nibble&2 != 0 {
			delta += step >> 1
		}

		if nibble&1 != 0 {
			delta += step >> 2
		}

		if nibble&8 != 0 {
			predictor -= delta
		} else {
			predictor += delta
		}

		predictor = clampPredictor(predictor)
		index = clampIndex(index + indexTable[nibble])
		pcm[i] = int16(predictor)
	}

	s.Predictor = int16(predictor)
	s.StepIndex = uint8(index)
}

func clampIndex(index int) int {
	switch {
	case index < 0:
		return 0
	case index > len(stepTable)-1:
		return len(stepTable) - 1
	default:
		return index
	}
}

func clampPredictor(predictor int) int {
	switch {
	case predictor < -32768:
		return -32768
	case predictor > 32767:
		return 32767
	default:
		return predictor
	}
}
