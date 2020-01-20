package main

import (
	"../hash-extender/hasher"
	"encoding/hex"
	"fmt"
)

func main() {
	var v  = hasher.CreateTigerHasher(0x80)
	digest := v.GetHash([]byte("The quick brown fox jumps over the lazy dog"))
	fmt.Printf("Digest %v\n", digest)
	fmt.Printf("Dig: %s\n", hex.EncodeToString(digest))

	//s := extender.CreateSigner(v)
	//fmt.Printf("Sign %v\n", hex.EncodeToString(s.GenerateSign([]byte("key"), []byte("message"), nil)))
	//fmt.Printf("Verify %v\n", s.VerifySign([]byte("key"), []byte("message"), s.GenerateSign([]byte("key"), []byte("messsage"), nil), nil))
	//

	//p := extender.CreateExtenderMD5(hasher.CreateMD5Hasher())
	//sign, _ := hex.DecodeString("4ff221af0ac2878285ec9b931cb67c02")
	//sign_new, res := p.GenerateExtension([]byte("count=10&lat=37.351&user_id=1&long=-119.827&waffle=eggo"), sign, []byte("&waffle=liege"), 14)
	//fmt.Printf("res: %v \n", hex.EncodeToString(sign_new))
	//fmt.Printf("res: %v \n", hex.EncodeToString(res))
	//
	//message := []byte("12345678901234")
	//message = append(message, res...)
	//digest = v.GetHash(message)
	//fmt.Printf("Dig: %s\n", hex.EncodeToString(digest))


}

