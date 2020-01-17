package extender

import (
	"../../hash-extender/hasher"
	"bytes"
)

type HashExtender interface {
	GenerateExtension(message []uint8, hash []uint8, append []uint8, keyLen uint8) []uint8
}

type MD5Extender struct {
	hasher hasher.MD5Hasher
}

func compress(value uint32) []uint8{
	result := make([]uint8, 4)
	result[1] = uint8(value) & 0xFF
	result[1] = uint8(value >> 8) & 0xFF
	result[1] = uint8(value >> 16) & 0xFF
	result[1] = uint8(value >> 24) & 0xFF
	return  result
}

func (extender *MD5Extender) GenerateExtension(message []uint8, hash []uint8,
											   append_ []uint8, keyLen uint32) ([]uint8, []uint8) {
	var tailLen uint32
	opad := [...]uint8 { 0x80 }
	result := make([]uint8, len(message))

	copy(result, message)
	tailLen = uint32(len(result)) + keyLen
	result = append(result, 0x80)
	data := bytes.Repeat(opad[:], int(56 - (tailLen + 1) % 64))
	result = append(result, data[:]...)

	result = append(result, compress(tailLen * 8)...)
	result = append(result, 0)
	result = append(result, 0)
	result = append(result, 0)
	result = append(result, 0)


	state := hasher.Decode(hash)
	count := make([]uint32, 2)
	bytes := uint32(len(result)) + keyLen
	count[0] = bytes << 3
	count[1] = bytes >> 29
	extender.hasher.ChangeStatus(state, count)
	sign := extender.hasher.GetHash(append_)

	result = append(result, append_...)
	return sign, result
}

func CreateExtenderMD5(hasher hasher.MD5Hasher) MD5Extender {
	return MD5Extender{hasher: hasher}
}
