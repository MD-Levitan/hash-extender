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
