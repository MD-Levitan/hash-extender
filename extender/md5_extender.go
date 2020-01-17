package extender

import (
	"../../hash-extender/hasher"
	"bytes"
)

type MD5Extender struct {
	hasher hasher.MD5Hasher
}

func (extender *MD5Extender) GenerateExtension(message []uint8, hash []uint8,
	append_ []uint8, keyLen uint32) ([]uint8, []uint8) {
	var tailLen uint32
	//var countv [2]uint32
	opad := [...]uint8 { 0x00 }
	result := make([]uint8, len(message))

	copy(result, message)
	tailLen = uint32(len(result)) + keyLen
	result = append(result, 0x80)
	data := bytes.Repeat(opad[:], int(56 - (tailLen + 1) % 64))
	result = append(result, data[:]...)

	//countv[1] = 0
	//countv[1] = tailLen * 8
	//fmt.Printf("count: %v \n", hasher.Encode(countv[:]))
	//result = append(result, hasher.Encode(countv[:])...)


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

