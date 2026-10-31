package adpcm

type State struct {
	Predictor int16
	StepIndex uint8
}

const (
	samplesPerByte    = 2
	nibbleBits        = 4
	nibbleMask        = 0x0f
	adpcmEighthShift  = 3
	adpcmQuarterShift = 2
	predictorMax      = 32767
)

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

func Encode(state *State, pcm []int16) []byte {
	encoded := make([]byte, (len(pcm)+1)/samplesPerByte)
	for sampleIndex, sample := range pcm {
		nibble := encodeSample(state, sample)
		if sampleIndex&1 == 0 {
			encoded[sampleIndex/samplesPerByte] = nibble
		} else {
			encoded[sampleIndex/samplesPerByte] |= nibble << nibbleBits
		}
	}

	return encoded
}

func Decode(state State, data []byte) []int16 {
	pcm := make([]int16, len(data)*samplesPerByte)
	decode(&state, data, pcm)

	return pcm
}

func encodeSample(state *State, sample int16) byte {
	index := clampIndex(int(state.StepIndex))
	predictor := int(state.Predictor)
	step := stepTable[index]
	difference := int(sample) - predictor
	nibble := byte(0)

	if difference < 0 {
		nibble = 8
		difference = -difference
	}

	delta := step >> adpcmEighthShift
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
	state.Predictor = int16(predictor)
	state.StepIndex = uint8(index)

	return nibble
}

func decode(state *State, data []byte, pcm []int16) {
	index := clampIndex(int(state.StepIndex))
	predictor := int(state.Predictor)

	for sampleIndex := range pcm {
		encoded := data[sampleIndex/samplesPerByte]
		shift := nibbleBits * (sampleIndex & 1)
		nibble := encoded >> shift & nibbleMask
		step := stepTable[index]
		delta := step >> adpcmEighthShift

		if nibble&4 != 0 {
			delta += step
		}

		if nibble&2 != 0 {
			delta += step >> 1
		}

		if nibble&1 != 0 {
			delta += step >> adpcmQuarterShift
		}

		if nibble&8 != 0 {
			predictor -= delta
		} else {
			predictor += delta
		}

		predictor = clampPredictor(predictor)
		index = clampIndex(index + indexTable[nibble])
		pcm[sampleIndex] = int16(predictor)
	}

	state.Predictor = int16(predictor)
	state.StepIndex = uint8(index)
}

func clampIndex(index int) int {
	switch {
	case index < 0:
		return 0

	case index >= len(stepTable):
		return len(stepTable) - 1

	default:
		return index
	}
}

func clampPredictor(predictor int) int {
	switch {
	case predictor < -32768:
		return -32768

	case predictor > predictorMax:
		return predictorMax

	default:
		return predictor
	}
}
