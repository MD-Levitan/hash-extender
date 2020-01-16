package main

import (
	"../hash-extender/extender"
	"../hash-extender/hasher"
	"encoding/hex"
	"fmt"
)

func main() {
	var v  = hasher.CreateHasher()
	digest := v.GetHash([]byte("d41d8cd98f00b204e9800998ecf8427ed41d8cd98f00b204e9800998ecf8427ed41d8cd98f00b204e9800998ecf8427ed41d8cd98f00b204e9800998ecf8427e"))
	fmt.Printf("Digest %v\n", digest)
	fmt.Printf("Dig: %s\n", hex.EncodeToString(digest))

	s := extender.CreateSigner(v)
	fmt.Printf("Sign %v\n", hex.EncodeToString(s.GenerateSign([]byte("key"), []byte("message"), nil)))
	fmt.Printf("Verify %v\n", s.VerifySign([]byte("key"), []byte("message"), s.GenerateSign([]byte("key"), []byte("messsage"), nil), nil))

	p := extender.CreateExtenderMD5(hasher.CreateMD5Hasher())
	sign, _ := hex.DecodeString("6d5f807e23db210bc254a28be2d6759a0f5f5d99")
	res := p.GenerateExtension([]byte("count=10&lat=37.351&user_id=1&long=-119.827&waffle=eggo"), sign, []byte("&waffle=liege"), 14)
	fmt.Printf("res: %v \n", res)
}

