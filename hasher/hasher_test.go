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

func TestTiger(t *testing.T){
	var a, b, c uint64 = 6280199717849618378, 8343645101657805456, 5997044206234503415
	var x = [...]uint64 {12062177936022666431, 11490956213547313652, 16829172008830410301,
		11899344311637024046,  3757253942274655973, 17835857420906997132,
		10787740079658512390,  17590610739856314589}
	//var mul uint8 = 9
	//round(&a, &b, &c, x[0], mul)
	//round(&b, &c, &a, x[1], mul)
	//round(&c, &a, &b, x[2], mul)
	//round(&a, &b, &c, x[3], mul)
	//round(&b, &c, &a, x[4], mul)
	//round(&c, &a, &b, x[5], mul)
	//round(&a, &b, &c, x[6], mul)
	//round(&b, &c, &a, x[7], mul)
	pass(&a, &b, &c, x[:], 9)
	if a != 1509595445172618351 {
		t.Errorf("value a is incorrect (caclulated %d, real %d)", a, 1509595445172618351)
	}


	if b != 206383248218352883 {
		t.Errorf("value b is incorrect (caclulated %d, real %d)", b, 206383248218352883)
	}


	if c != 2725617220977123037 {
		t.Errorf("value c is incorrect (caclulated %d, real %d)", c, 2725617220977123037)
	}

}

func TestTigerUpdate(t *testing.T) {
	var hasher = CreateTigerHasherPrivate(0x01)
	var data = []byte("TigerTigerTigerTigerTigerTigerTigerTigerTigerTigerTigerTigerTige")
	var state = [...]uint64{81985529216486895, 18364758544493064720, 17336226011405279623}
	hasher.ChangeStatus(state[:], make([]uint32, 2))
	hasher.Transform(data)
	if hasher.state[0] != 0x29CCDEE812891C0F {
		t.Errorf("Update work wrong")
	}
	if hasher.state[1] != 0xA18BA64634ACD11A {
		t.Errorf("Update work wrong")
	}
	if hasher.state[2] != 0x5FA4D4854FCE7BCA {
		t.Errorf("Update work wrong")
	}
}