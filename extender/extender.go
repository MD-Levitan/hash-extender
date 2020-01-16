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

func (extender *MD5Extender) GenerateExtension(message []uint8, hash []uint8, append_ []uint8, keyLen uint32) []uint8 {
	var tailLen uint32
	var result []uint8
	opad := [...]uint8 { 0x80 }
	copy(result, message)
	tailLen = uint32(len(result)) + keyLen
	tailLen *= 8
	result = append(result, 0x80)
	data := bytes.Repeat(opad[:], int(56 - (tailLen + 1) % 64))
	result = append(result, data[:]...)

	result = append(result, uint8(tailLen) & 0xFF)
	result = append(result, uint8(tailLen >> 8) & 0xFF)
	result = append(result, uint8(tailLen >> 16) & 0xFF)
	result = append(result, uint8(tailLen >> 24) & 0xFF)
	result = append(result, 0)
	result = append(result, 0)
	result = append(result, 0)
	result = append(result, 0)

	state := hasher.Decode(hash)
	count := make([]uint32, 2)
	count[0] = (uint32(len(result)) + keyLen) * 8
	extender.hasher.ChangeStatus(state, count)
	sign := extender.hasher.GetHash(append_)
	result = append(result, sign...)
	return result
}

func CreateExtenderMD5(hasher hasher.MD5Hasher) MD5Extender {
	return MD5Extender{hasher: hasher}
}