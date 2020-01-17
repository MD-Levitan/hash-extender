package hasher

import (
	"fmt"
	"unsafe"
)

type SHA1Hasher struct {
	/* State of the hasher */
	state 		[5]uint32
	count 		[2]uint32
	buffer 		[64]uint8
}

const HASH_SIZE_SHA1 = 20

func rol(value uint32, bits uint8) uint32 {
	return ((value) << (bits)) | ((value) >> (32 - (bits)))
}

func blk0(blk *[]uint32, i uint8)  uint32 {
	(*blk)[i] = (rol((*blk)[i],24) & 0xFF00FF00) | (rol((*blk)[i],8) & 0x00FF00FF)
	return  (*blk)[i]
}

func blk1(blk *[]uint32, i uint8)  uint32 {
	(*blk)[i & 15] = rol((*blk)[(i + 13) & 15] ^ (*blk)[(i + 8) & 15] ^ (*blk)[(i + 2) & 15] ^ (*blk)[i & 15],1)
	return (*blk)[i & 15]
}

func r0(v uint32, w *uint32, x uint32, y uint32, z *uint32, i uint8, blk *[]uint32){
	*z += ((*w & (x ^ y)) ^ y) + blk0(blk, i) + 0x5A827999 + rol(v,5)
	*w = rol(*w,30)
}

func r1(v uint32, w *uint32, x uint32, y uint32, z *uint32, i uint8, blk *[]uint32){
	*z += ((*w & (x ^ y)) ^ y) + blk1(blk, i) + 0x5A827999 + rol(v,5)
	*w = rol(*w,30)
}

func r2(v uint32, w *uint32, x uint32, y uint32, z *uint32, i uint8, blk *[]uint32){
	*z += (*w ^ x ^ y) + blk1(blk, i) + 0x6ED9EBA1 + rol(v,5)
	*w = rol(*w,30)
}

func r3(v uint32, w *uint32, x uint32, y uint32, z *uint32, i uint8, blk *[]uint32){
	*z += ((( *w | x) & y) | (*w & x)) + blk1(blk, i) + 0x8F1BBCDC + rol(v,5)
	*w = rol(*w,30)
}

func r4(v uint32, w *uint32, x uint32, y uint32, z *uint32, i uint8, blk *[]uint32){
	*z += (*w ^ x ^ y) + blk1(blk, i) + 0xCA62C1D6 + rol(v,5)
	*w = rol(*w,30)
}

/* SHA1 basic transformation. Transforms state based on block */
func (hasher *SHA1Hasher) Transform(block []uint8) {
	var a, b, c, d, e = hasher.state[0], hasher.state[1], hasher.state[2], hasher.state[3], hasher.state[4]
	var blk = make([]uint32, 64)

	dst := (*[]uint8)(unsafe.Pointer(&blk))
	copy(*dst, block[:64])

	/* 4 rounds of 20 operations each. Loop unrolled. */
	r0(a, &b, c, d, &e, 0, &blk)
	r0(e, &a, b, c, &d, 1, &blk)
	r0(d, &e, a, b, &c, 2, &blk)
	r0(c, &d, e, a, &b, 3, &blk)
	r0(b, &c, d, e, &a, 4, &blk)
	r0(a, &b, c, d, &e, 5, &blk)
	r0(e, &a, b, c, &d, 6, &blk)
	r0(d, &e, a, b, &c, 7, &blk)
	r0(c, &d, e, a, &b, 8, &blk)
	r0(b, &c, d, e, &a, 9, &blk)
	r0(a, &b, c, d, &e, 10, &blk)
	r0(e, &a, b, c, &d, 11, &blk)
	r0(d, &e, a, b, &c, 12, &blk)
	r0(c, &d, e, a, &b, 13, &blk)
	r0(b, &c, d, e, &a, 14, &blk)
	r0(a, &b, c, d, &e, 15, &blk)
	r1(e, &a, b, c, &d, 16, &blk)
	r1(d, &e, a, b, &c, 17, &blk)
	r1(c, &d, e, a, &b, 18, &blk)
	r1(b, &c, d, e, &a, 19, &blk)
	r2(a, &b, c, d, &e, 20, &blk)
	r2(e, &a, b, c, &d, 21, &blk)
	r2(d, &e, a, b, &c, 22, &blk)
	r2(c, &d, e, a, &b, 23, &blk)
	r2(b, &c, d, e, &a, 24, &blk)
	r2(a, &b, c, d, &e, 25, &blk)
	r2(e, &a, b, c, &d, 26, &blk)
	r2(d, &e, a, b, &c, 27, &blk)
	r2(c, &d, e, a, &b, 28, &blk)
	r2(b, &c, d, e, &a, 29, &blk)
	r2(a, &b, c, d, &e, 30, &blk)
	r2(e, &a, b, c, &d, 31, &blk)
	r2(d, &e, a, b, &c, 32, &blk)
	r2(c, &d, e, a, &b, 33, &blk)
	r2(b, &c, d, e, &a, 34, &blk)
	r2(a, &b, c, d, &e, 35, &blk)
	r2(e, &a, b, c, &d, 36, &blk)
	r2(d, &e, a, b, &c, 37, &blk)
	r2(c, &d, e, a, &b, 38, &blk)
	r2(b, &c, d, e, &a, 39, &blk)
	r3(a, &b, c, d, &e, 40, &blk)
	r3(e, &a, b, c, &d, 41, &blk)
	r3(d, &e, a, b, &c, 42, &blk)
	r3(c, &d, e, a, &b, 43, &blk)
	r3(b, &c, d, e, &a, 44, &blk)
	r3(a, &b, c, d, &e, 45, &blk)
	r3(e, &a, b, c, &d, 46, &blk)
	r3(d, &e, a, b, &c, 47, &blk)
	r3(c, &d, e, a, &b, 48, &blk)
	r3(b, &c, d, e, &a, 49, &blk)
	r3(a, &b, c, d, &e, 50, &blk)
	r3(e, &a, b, c, &d, 51, &blk)
	r3(d, &e, a, b, &c, 52, &blk)
	r3(c, &d, e, a, &b, 53, &blk)
	r3(b, &c, d, e, &a, 54, &blk)
	r3(a, &b, c, d, &e, 55, &blk)
	r3(e, &a, b, c, &d, 56, &blk)
	r3(d, &e, a, b, &c, 57, &blk)
	r3(c, &d, e, a, &b, 58, &blk)
	r3(b, &c, d, e, &a, 59, &blk)
	r4(a, &b, c, d, &e, 60, &blk)
	r4(e, &a, b, c, &d, 61, &blk)
	r4(d, &e, a, b, &c, 62, &blk)
	r4(c, &d, e, a, &b, 63, &blk)
	r4(b, &c, d, e, &a, 64, &blk)
	r4(a, &b, c, d, &e, 65, &blk)
	r4(e, &a, b, c, &d, 66, &blk)
	r4(d, &e, a, b, &c, 67, &blk)
	r4(c, &d, e, a, &b, 68, &blk)
	r4(b, &c, d, e, &a, 69, &blk)
	r4(a, &b, c, d, &e, 70, &blk)
	r4(e, &a, b, c, &d, 71, &blk)
	r4(d, &e, a, b, &c, 72, &blk)
	r4(c, &d, e, a, &b, 73, &blk)
	r4(b, &c, d, e, &a, 74, &blk)
	r4(a, &b, c, d, &e, 75, &blk)
	r4(e, &a, b, c, &d, 76, &blk)
	r4(d, &e, a, b, &c, 77, &blk)
	r4(c, &d, e, a, &b, 78, &blk)
	r4(b, &c, d, e, &a, 79, &blk)
	/* Add the working vars back into context.state[] */

	hasher.state[0] += a
	hasher.state[1] += b
	hasher.state[2] += c
	hasher.state[3] += d
	hasher.state[4] += e

	/* Wipe variables ?add*/
}

/* SHA1 change status-values in struct */
func (hasher *SHA1Hasher) ChangeStatus(state []uint32, count []uint32){
	copy(hasher.state[:], state[:])
	copy(hasher.count[:], count[:])
}

/* SHA1 Update status */
func (hasher *SHA1Hasher) Update(data []uint8) {
	var i,j uint32
	dataLen := uint32(len(data))

	j = hasher.count[0]
	hasher.count[0] += dataLen << 3
	if hasher.count[0] < j {
		hasher.count[1] ++
	}
	hasher.count[1] += dataLen >> 29
	j = (j >> 3) & 63
	if j +  dataLen > 63 {
		i = 64 - j
		copy(hasher.buffer[j:], data[:i])
		hasher.Transform(hasher.buffer[:])
		for ; i + 63 < dataLen; i += 64 {
			hasher.Transform(data[i:])
		}
		j = 0
	} else {
		i = 0
	}
	copy(hasher.buffer[j:], data[i:])
}

func (hasher *SHA1Hasher) Final() []uint8 {
	var digest [HASH_SIZE_SHA1]uint8
	var finalCount = make([]uint8, 8)
	var c = [...]uint8{0200,}

	for i := 0; i < 8; i++  {
		j := 1
		if i >= 4 {
			j = 0
		}
		finalCount[i] = uint8(hasher.count[j] >> ((3-(i & 3)) * 8) & 255)
	}
	hasher.Update(c[:])
	for ok := hasher.count[0] & 504; ok != 448; ok = hasher.count[0] & 504 {
		c[0] = 000
		hasher.Update(c[:])
	}
	hasher.Update(finalCount)

	for i := 0; i < 20; i++ {
		digest[i] = uint8(hasher.state[i >> 2] >> ((3-(i & 3)) * 8)) & 255
	}
	return digest[:]
}

func (hasher *SHA1Hasher) Reset() {
	hasher.state[0] = 0x67452301
	hasher.state[1] = 0xefcdab89
	hasher.state[2] = 0x98badcfe
	hasher.state[3] = 0x10325476
	hasher.state[4] = 0xC3D2E1F0
	hasher.count[0] = 0
	hasher.count[1] = 0
}

func (hasher *SHA1Hasher) GetHash(data []uint8) []uint8 {
	hasher.Update(data)
	digest := hasher.Final()
	hasher.Reset()
	return digest[:]
}

func (hasher SHA1Hasher) GetHashSize() uint32 {
	return HASH_SIZE_SHA1
}

func (hasher SHA1Hasher) PrintStatus() {
	fmt.Printf("Hasher:\n")
	fmt.Printf("\t\tstate: %v\n", hasher.state)
	fmt.Printf("\t\tcount: %v\n", hasher.count)
	fmt.Printf("\t\tbuffer: %v\n\n", hasher.buffer)

}

func CreateSHA1HasherPrivate() SHA1Hasher {
	hasher := SHA1Hasher{}
	hasher.Reset()
	return hasher
}

func CreateSha1Hasher() Hasher {
	hasher := SHA1Hasher{}
	hasher.Reset()
	return &hasher
}