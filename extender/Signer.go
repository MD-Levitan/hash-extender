package extender

import (
	"../../hash-extender/hasher"
	"bytes"
)

type Signer struct {
	hasher hasher.Hasher
}

func simple_concat(key []uint8, message []uint8) []uint8 {
	result := make([]uint8, len(key) + len(message))
	copy(result, key)
	copy(result[len(key):], message)
	return result
}

/* Generate Sign, concat may be nil */
func (signer Signer) GenerateSign(key []uint8, message []uint8, concat func([]uint8, []uint8) []uint8) []uint8 {
	if concat == nil{
		concat = simple_concat
	}
	return signer.hasher.GetHash(concat(key, message))
}

/* Verify Sign, concat may be nil */
func (signer Signer) VerifySign(key []uint8, message []uint8, sign []uint8,
								concat func([]uint8, []uint8) []uint8) bool {
	if concat == nil{
		concat = simple_concat
	}
	signReal := signer.hasher.GetHash(concat(key, message))
	return  bytes.Compare(signReal, sign) == 0
}

func CreateSigner(hasher hasher.Hasher) Signer {
	return Signer{hasher: hasher}
}