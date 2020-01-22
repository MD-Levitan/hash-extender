package extender

import (
	"../../hash-extender/hasher"
	"bytes"
)


type TigerExtender struct {
	hasher hasher.TigerHasher
}

func (extender *TigerExtender) GenerateExtension(message []uint8, hash []uint8,
	append_ []uint8, keyLen uint32) ([]uint8, []uint8) {
	var tailLen uint32
	opad := [...]uint8 { 0x00 }
	result := make([]uint8, len(message))

	copy(result, message)


	tailLen = uint32(len(result)) + keyLen
	result = append(result, extender.hasher.GetPad())
	data := bytes.Repeat(opad[:], int(56 - (tailLen + 1) % 64))
	result = append(result, data[:]...)

	result = append(result, compress(tailLen * 8)...)
	result = append(result, 0)
	result = append(result, 0)
	result = append(result, 0)
	result = append(result, 0)



	state := hasher.Decode64(hash)
	count := make([]uint32, 2)
	bytes := uint32(len(result)) + keyLen
	count[0] = bytes << 3
	count[1] = bytes >> 29
	extender.hasher.ChangeStatus(state, count)
	sign := extender.hasher.GetHash(append_)

	result = append(result, append_...)
	return sign, result
}

func CreateExtenderTiger(hasher hasher.TigerHasher) TigerExtender {
	return TigerExtender{hasher: hasher}
}
