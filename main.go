package main

import (
	"../hash-extender/extender"
	"../hash-extender/hasher"
	"encoding/hex"
	"fmt"
)

func main() {
	v := hasher.CreateMD5Hasher()
	digest := v.GetHash([]byte("d41d8cd98f00b204e9800998ecf8427ed41d8cd98f00b204e9800998ecf8427ed41d8cd98f00b204e9800998ecf8427ed41d8cd98f00b204e9800998ecf8427e"))
	fmt.Printf("Digest %v\n", digest)
	fmt.Printf("Dig: %s\n", hex.EncodeToString(digest))

	s := extender.CreateSigner(v)
	fmt.Printf("Sign %v\n", hex.EncodeToString(s.GenerateSign([]byte("key"), []byte("message"), nil)))
	fmt.Printf("Verify %v\n", s.VerifySign([]byte("key"), []byte("message"), s.GenerateSign([]byte("key"), []byte("messsage"), nil), nil))
}
