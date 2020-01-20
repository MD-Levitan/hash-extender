package hasher

type Hasher interface {
	/* */
	GetHash([]uint8) []uint8

	/**/
	GetHashSize() uint32
	/**/
	Reset()
}

///* Private interface for creating Extender */
//type PrivateHasher interface {
//	/* */
//	Update(data []uint8)
//
//	/* Transform */
//	Transform([]uint8)
//
//	ChangeStatus(*PrivateHasher)
//
//	/**/
//	Final() []uint8
//}

func Encode(input []uint32) []uint8 {
	output := make([]uint8, len(input) * 4)
	for i, j := 0, 0; j < len(output); i, j = i + 1, j + 4 {
		output[j] = uint8(input[i] & 0xff)
		output[j+1] = uint8((input[i] >> 8) & 0xff)
		output[j+2] = uint8((input[i] >> 16) & 0xff)
		output[j+3] = uint8((input[i] >> 24) & 0xff)
	}
	return output
}

func Encode2(input []uint32) []uint8 {
	output := make([]uint8, len(input) * 4)
	for i, j := 0, 0; j < len(output); i, j = i + 1, j + 4 {
		output[j+3] = uint8(input[i] & 0xff)
		output[j+2] = uint8((input[i] >> 8) & 0xff)
		output[j+1] = uint8((input[i] >> 16) & 0xff)
		output[j+0] = uint8((input[i] >> 24) & 0xff)
	}
	return output
}

func Decode64(input []uint8) []uint64 {
	output := make([]uint64, len(input) / 8)
	for i, j := 0, 0; j < len(input); i, j = i + 1, j + 8 {
		output[i] = (uint64(input[j+0]) << 00) |
			(uint64(input[j+1]) << 8) |
			(uint64(input[j+2]) << 16) |
			(uint64(input[j+3]) << 24) |
			(uint64(input[j+4]) << 32) |
			(uint64(input[j+5]) << 40) |
			(uint64(input[j+6]) << 48) |
			(uint64(input[j+7]) << 56)

	}
	return output
}

func Decode642(input []uint8) []uint64 {
	output := make([]uint64, len(input) / 8)
	for i, j := 0, 0; j < len(input); i, j = i + 1, j + 8 {
		output[i] = (uint64(input[j+7]) << 00) |
			(uint64(input[j+6]) << 8) |
			(uint64(input[j+5]) << 16) |
			(uint64(input[j+4]) << 24) |
			(uint64(input[j+3]) << 32) |
			(uint64(input[j+2]) << 40) |
			(uint64(input[j+1]) << 48) |
			(uint64(input[j+0]) << 56)

	}
	return output
}

func Decode(input []uint8) []uint32 {
	output := make([]uint32, len(input) / 4)
	for i, j := 0, 0; j < len(input); i, j = i + 1, j + 4 {
		output[i] = (uint32(input[j+0]) << 00) |
			(uint32(input[j+1]) << 8) |
			(uint32(input[j+2]) << 16) |
			(uint32(input[j+3]) << 24)
	}
	return output
}

func Decode2(input []uint8) []uint32 {
	output := make([]uint32, len(input) / 4)
	for i, j := 0, 0; j < len(input); i, j = i + 1, j + 4 {
		output[i] = (uint32(input[j+3]) << 00) |
			(uint32(input[j+2]) << 8) |
			(uint32(input[j+1]) << 16) |
			(uint32(input[j+0]) << 24)
	}
	return output
}