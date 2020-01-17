package extender

type HashExtender interface {
	GenerateExtension(message []uint8, hash []uint8, append []uint8, keyLen uint8) []uint8
}

func compress(value uint32) []uint8{
	result := make([]uint8, 4)
	result[0] = uint8(value) & 0xFF
	result[1] = uint8(value >> 8) & 0xFF
	result[2] = uint8(value >> 16) & 0xFF
	result[3] = uint8(value >> 24) & 0xFF
	return  result
}

func compress2(value uint32) []uint8{
	result := make([]uint8, 4)
	result[3] = uint8(value) & 0xFF
	result[2] = uint8(value >> 8) & 0xFF
	result[1] = uint8(value >> 16) & 0xFF
	result[0] = uint8(value >> 24) & 0xFF
	return  result
}