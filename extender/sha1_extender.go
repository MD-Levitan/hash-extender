package extender

import (
	"../../hash-extender/hasher"
	"bytes"
)

type SHA1Extender struct {
	hasher hasher.SHA1Hasher
}

func (extender *SHA1Extender) GenerateExtension(message []uint8, hash []uint8,
	append_ []uint8, keyLen uint32) ([]uint8, []uint8) {
	var tailLen uint32
	opad := [...]uint8 { 0x00 }
	result := make([]uint8, len(message))

	copy(result, message)


	tailLen = uint32(len(result)) + keyLen
	result = append(result, 0x80)
	data := bytes.Repeat(opad[:], int(56 - (tailLen + 1) % 64))
	result = append(result, data[:]...)

	result = append(result, 0)
	result = append(result, 0)
	result = append(result, 0)
	result = append(result, 0)
	result = append(result, compress2(tailLen * 8)...)


	state := hasher.Decode2(hash)
	count := make([]uint32, 2)
	bytes := uint32(len(result)) + keyLen
	count[0] = bytes << 3
	count[1] = bytes >> 29
	extender.hasher.ChangeStatus(state, count)
	sign := extender.hasher.GetHash(append_)

	result = append(result, append_...)
	return sign, result
}

func CreateExtenderSHA1(hasher hasher.SHA1Hasher) SHA1Extender {
	return SHA1Extender{hasher: hasher}
}

