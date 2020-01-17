package extender

import (
	"../../hash-extender/hasher"
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestSHA1Extender_GenerateExtension(t *testing.T) {
	key := []byte("NoNeedToRecoverKey")
	message := []byte("SecuredResource")
	append_data := []byte("TheResourceRemainsUnsecured")

	v := hasher.CreateSHA1HasherPrivate()
	s := CreateSigner(hasher.CreateSha1Hasher())
	sign := s.GenerateSign(key, message,nil)
	fmt.Printf("sign: %v \n", hex.EncodeToString(sign))


	p := CreateExtenderSHA1(v)
	signNew, newMessage := p.GenerateExtension(message, sign, append_data, 18)
	fmt.Printf("res: %v \n", hex.EncodeToString(signNew))
	fmt.Printf("res: %v \n", hex.EncodeToString(newMessage))

	signReal := v.GetHash(append(key, newMessage...))
	fmt.Printf("Dig: %s\n", hex.EncodeToString(signReal))
	if bytes.Compare(signReal, signNew) != 0 {
		t.Errorf("Algorithm doesn't work properly")
	}
}

func TestMD5Extender_GenerateExtensionExtender_GenerateExtension(t *testing.T) {
	key := []byte("NoNeedToRecoverKey")
	message := []byte("SecuredResource")
	append_data := []byte("TheResourceRemainsUnsecured")

	v := hasher.CreateMD5HasherPrivate()
	s := CreateSigner(hasher.CreateMD5Hasher())
	sign := s.GenerateSign(key, message,nil)
	fmt.Printf("sign: %v \n", hex.EncodeToString(sign))


	p := CreateExtenderMD5(v)
	signNew, newMessage := p.GenerateExtension(message, sign, append_data, 18)
	fmt.Printf("res: %v \n", hex.EncodeToString(signNew))
	fmt.Printf("res: %v \n", newMessage)

	signReal := v.GetHash(append(key, newMessage...))
	fmt.Printf("Dig: %s\n", hex.EncodeToString(signReal))
	if bytes.Compare(signReal, signNew) != 0 {
		t.Errorf("Algorithm doesn't work properly")
	}
}
