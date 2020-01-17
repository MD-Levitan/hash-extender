package hasher

import (
	"encoding/hex"
	"testing"
)

func TestSha1BytesEmpty(t *testing.T) {
	hasher := CreateSha1Hasher()
	bytes := hasher.GetHash([]byte(""))
	hexBytes := hex.EncodeToString(bytes)
	if hexBytes != "da39a3ee5e6b4b0d3255bfef95601890afd80709" {
		t.Errorf("Calculated hash %s in incorrect, valid hash is %s\n",
			hexBytes, "da39a3ee5e6b4b0d3255bfef95601890afd80709")
	}
}

func TestSha1Bytes1(t *testing.T) {
	hasher := CreateSha1Hasher()
	bytes := hasher.GetHash([]byte("TestTextForSHA1\\\\"))
	hexBytes := hex.EncodeToString(bytes)
	if hexBytes != "d0b27dbaa5963397ab3c46bcbc7f680544e25fc7" {
		t.Errorf("Calculated hash %s in incorrect, valid hash is %s\n",
			hexBytes, "d0b27dbaa5963397ab3c46bcbc7f680544e25fc7")
	}
}

func TestSha1BytesSize(t *testing.T) {
	hasher := CreateSha1Hasher()
	if hasher.GetHashSize() != HASH_SIZE_SHA1 {
		t.Errorf("Size incorrect")
	}
}

func TestMD5BytesEmpty(t *testing.T) {
	hasher := CreateMD5Hasher()
	bytes := hasher.GetHash([]byte(""))
	hexBytes := hex.EncodeToString(bytes)
	if hexBytes != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Errorf("Calculated hash %s in incorrect, valid hash is %s\n",
			hexBytes, "d41d8cd98f00b204e9800998ecf8427e")
	}
}

func TestMD5Bytes1(t *testing.T) {
	hasher := CreateMD5Hasher()
	bytes := hasher.GetHash([]byte("TestTextForSHA1\\\\"))
	hexBytes := hex.EncodeToString(bytes)
	if hexBytes != "7b7c2c0b016e20a7001abfe1a4a00aaa" {
		t.Errorf("Calculated hash %s in incorrect, valid hash is %s\n",
			hexBytes, "7b7c2c0b016e20a7001abfe1a4a00aaa")
	}
}

func TestMD5Bytes2(t *testing.T) {
	hasher := CreateMD5Hasher()
	bytes := hasher.GetHash([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
	hexBytes := hex.EncodeToString(bytes)
	if hexBytes != "27fd6842da77a8c92c9804277f5cf3f4" {
		t.Errorf("Calculated hash %s in incorrect, valid hash is %s\n",
			hexBytes, "27fd6842da77a8c92c9804277f5cf3f4")
	}
}