package hasher

type Hasher interface {
	/* */
	GetHash(data []uint8) []uint8

	/**/
	GetHashSize() uint32
	/**/
	Reset()
}

/******************** MD5 **********************/

type MD5Hasher struct {
	/* State of the hasher */
	state 		[5]uint32
	count 		[2]uint32
	buffer 		[64]uint8
}

const HASH_SIZE_MD5 = 16

var PADDING = [...]uint8 {
0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }

const S11, S12, S13, S14, S21, S22, S23, S24, S31, S32, S33, S34, S41, S42, S43, S44 =
	7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21

func F(x uint32, y uint32, z uint32) uint32 {
	return ((x) & (y)) | ((^x) & (z))
}
func G(x uint32, y uint32, z uint32) uint32 {
	return ((x) & (z)) | ((y) & (^z))
}
func H(x uint32, y uint32, z uint32) uint32 {
	return (x) ^ (y) ^ (z)
}
func I(x uint32, y uint32, z uint32) uint32 {
	return(y) ^ ((x) | (^z))
}

func rotateLeft(x uint32, n uint8) uint32 {
	return ((x) << (n)) | ((x) >> (32 - (n)))
}

func transform(a *uint32, b uint32, c uint32, d uint32, x uint32, s uint8, ac uint32,
			   fun func(x uint32, y uint32, z uint32) uint32) {
	*a += fun(b, c, d) + x + ac
	*a = rotateLeft(*a, s)
	*a += b
}

func FF(a *uint32, b uint32, c uint32, d uint32, x uint32, s uint8, ac uint32) {
	transform(a, b, c, d, x, s, ac, F)
}

func GG(a *uint32, b uint32, c uint32, d uint32, x uint32, s uint8, ac uint32) {
	transform(a, b, c, d, x, s, ac, G)
}

func HH(a *uint32, b uint32, c uint32, d uint32, x uint32, s uint8, ac uint32) {
	transform(a, b, c, d, x, s, ac, H)
}

func II(a *uint32, b uint32, c uint32, d uint32, x uint32, s uint8, ac uint32) {
	transform(a, b, c, d, x, s, ac, I)
}

func encode(input []uint32) []uint8 {
	output := make([]uint8, len(input) * 4)
	for i, j := 0, 0; j < len(output); i, j = i + 1, j + 4 {
		output[j] = uint8(input[i] & 0xff)
		output[j+1] = uint8((input[i] >> 8) & 0xff)
		output[j+2] = uint8((input[i] >> 16) & 0xff)
		output[j+3] = uint8((input[i] >> 24) & 0xff)
	}
	return output
}

func decode(input []uint8) []uint32 {
	output := make([]uint32, len(input) / 4)
	for i, j := 0, 0; j < len(input); i, j = i + 1, j + 4 {
		output[i] = uint32(input[j]) | (uint32(input[j+1]) << 8) |
					  (uint32(input[j+2]) << 16) | (uint32(input[j+3]) << 24)
	}
	return output
}

/* MD5 basic transformation. Transforms state based on block */
func (hasher *MD5Hasher) transformMD5(block []uint8) {
	var a,b,c,d = hasher.state[0], hasher.state[1], hasher.state[2], hasher.state[3]
	var x = decode(block[:])

	/* Round 1 */
	FF(&a, b, c, d, x[ 0], S11, 0xd76aa478) /* 1 */
	FF(&d, a, b, c, x[ 1], S12, 0xe8c7b756) /* 2 */
	FF(&c, d, a, b, x[ 2], S13, 0x242070db) /* 3 */
	FF(&b, c, d, a, x[ 3], S14, 0xc1bdceee) /* 4 */
	FF(&a, b, c, d, x[ 4], S11, 0xf57c0faf) /* 5 */
	FF(&d, a, b, c, x[ 5], S12, 0x4787c62a) /* 6 */
	FF(&c, d, a, b, x[ 6], S13, 0xa8304613) /* 7 */
	FF(&b, c, d, a, x[ 7], S14, 0xfd469501) /* 8 */
	FF(&a, b, c, d, x[ 8], S11, 0x698098d8) /* 9 */
	FF(&d, a, b, c, x[ 9], S12, 0x8b44f7af) /* 10 */
	FF(&c, d, a, b, x[10], S13, 0xffff5bb1) /* 11 */
	FF(&b, c, d, a, x[11], S14, 0x895cd7be) /* 12 */
	FF(&a, b, c, d, x[12], S11, 0x6b901122) /* 13 */
	FF(&d, a, b, c, x[13], S12, 0xfd987193) /* 14 */
	FF(&c, d, a, b, x[14], S13, 0xa679438e) /* 15 */
	FF(&b, c, d, a, x[15], S14, 0x49b40821) /* 16 */

	/* Round 2 */
	GG(&a, b, c, d, x[ 1], S21, 0xf61e2562) /* 17 */
	GG(&d, a, b, c, x[ 6], S22, 0xc040b340) /* 18 */
	GG(&c, d, a, b, x[11], S23, 0x265e5a51) /* 19 */
	GG(&b, c, d, a, x[ 0], S24, 0xe9b6c7aa) /* 20 */
	GG(&a, b, c, d, x[ 5], S21, 0xd62f105d) /* 21 */
	GG(&d, a, b, c, x[10], S22, 0x2441453)  /* 22 */
	GG(&c, d, a, b, x[15], S23, 0xd8a1e681) /* 23 */
	GG(&b, c, d, a, x[ 4], S24, 0xe7d3fbc8) /* 24 */
	GG(&a, b, c, d, x[ 9], S21, 0x21e1cde6) /* 25 */
	GG(&d, a, b, c, x[14], S22, 0xc33707d6) /* 26 */
	GG(&c, d, a, b, x[ 3], S23, 0xf4d50d87) /* 27 */
	GG(&b, c, d, a, x[ 8], S24, 0x455a14ed) /* 28 */
	GG(&a, b, c, d, x[13], S21, 0xa9e3e905) /* 29 */
	GG(&d, a, b, c, x[ 2], S22, 0xfcefa3f8) /* 30 */
	GG(&c, d, a, b, x[ 7], S23, 0x676f02d9) /* 31 */
	GG(&b, c, d, a, x[12], S24, 0x8d2a4c8a) /* 32 */

	/* Round 3 */
	HH(&a, b, c, d, x[ 5], S31, 0xfffa3942) /* 33 */
	HH(&d, a, b, c, x[ 8], S32, 0x8771f681) /* 34 */
	HH(&c, d, a, b, x[11], S33, 0x6d9d6122) /* 35 */
	HH(&b, c, d, a, x[14], S34, 0xfde5380c) /* 36 */
	HH(&a, b, c, d, x[ 1], S31, 0xa4beea44) /* 37 */
	HH(&d, a, b, c, x[ 4], S32, 0x4bdecfa9) /* 38 */
	HH(&c, d, a, b, x[ 7], S33, 0xf6bb4b60) /* 39 */
	HH(&b, c, d, a, x[10], S34, 0xbebfbc70) /* 40 */
	HH(&a, b, c, d, x[13], S31, 0x289b7ec6) /* 41 */
	HH(&d, a, b, c, x[ 0], S32, 0xeaa127fa) /* 42 */
	HH(&c, d, a, b, x[ 3], S33, 0xd4ef3085) /* 43 */
	HH(&b, c, d, a, x[ 6], S34, 0x4881d05)  /* 44 */
	HH(&a, b, c, d, x[ 9], S31, 0xd9d4d039) /* 45 */
	HH(&d, a, b, c, x[12], S32, 0xe6db99e5) /* 46 */
	HH(&c, d, a, b, x[15], S33, 0x1fa27cf8) /* 47 */
	HH(&b, c, d, a, x[ 2], S34, 0xc4ac5665) /* 48 */

	/* Round 4 */
	II(&a, b, c, d, x[ 0], S41, 0xf4292244) /* 49 */
	II(&d, a, b, c, x[ 7], S42, 0x432aff97) /* 50 */
	II(&c, d, a, b, x[14], S43, 0xab9423a7) /* 51 */
	II(&b, c, d, a, x[ 5], S44, 0xfc93a039) /* 52 */
	II(&a, b, c, d, x[12], S41, 0x655b59c3) /* 53 */
	II(&d, a, b, c, x[ 3], S42, 0x8f0ccc92) /* 54 */
	II(&c, d, a, b, x[10], S43, 0xffeff47d) /* 55 */
	II(&b, c, d, a, x[ 1], S44, 0x85845dd1) /* 56 */
	II(&a, b, c, d, x[ 8], S41, 0x6fa87e4f) /* 57 */
	II(&d, a, b, c, x[15], S42, 0xfe2ce6e0) /* 58 */
	II(&c, d, a, b, x[ 6], S43, 0xa3014314) /* 59 */
	II(&b, c, d, a, x[13], S44, 0x4e0811a1) /* 60 */
	II(&a, b, c, d, x[ 4], S41, 0xf7537e82) /* 61 */
	II(&d, a, b, c, x[11], S42, 0xbd3af235) /* 62 */
	II(&c, d, a, b, x[ 2], S43, 0x2ad7d2bb) /* 63 */
	II(&b, c, d, a, x[ 9], S44, 0xeb86d391) /* 64 */

	hasher.state[0] += a
	hasher.state[1] += b
	hasher.state[2] += c
	hasher.state[3] += d
}

func (hasher *MD5Hasher) updateMD5(data []uint8) {
	var i, index, partLen uint32
	inputLen := uint32(len(data))

	/* Compute number of bytes mod 64 */
	index = (hasher.count[0] >> 3) & 0x3F

	hasher.count[0] += inputLen << 3
	/* Update number of bits */
	if hasher.count[0] < (inputLen << 3) {
		hasher.count[1]++
	}
	hasher.count[1] += inputLen >> 29

	partLen = 64 - index

	/* Transform as many times as possible. */
	if inputLen >= partLen {
		copy(hasher.buffer[index:], data[0:partLen])
		hasher.transformMD5(hasher.buffer[:])
		for i:=partLen; i + 63 < inputLen; i += 64 {
			hasher.transformMD5(data[i:])
		}
		index = 0
	} else {
		i = 0
	}

	/* Buffer remaining input */
	copy(hasher.buffer[index:], data[i:])
}

func (hasher *MD5Hasher) finalMD5() [HASH_SIZE_MD5]uint8 {
	var index, padLen uint32
	var digest [16]uint8
	bits := encode(hasher.count[0:2])

	/* Pad out to 56 mod 64. */
	index = (hasher.count[0] >> 3) & 0x3f
	padLen = 56 - index
	if index >= 56 {
		padLen = 120 - index
	}
	hasher.updateMD5(PADDING[0:padLen])

	/* Append length (before padding) */
	hasher.updateMD5(bits[0:8])

	copy(digest[:], encode(hasher.state[0:4]))
	return digest
}

func (hasher *MD5Hasher) Reset() {
	hasher.state[0] = 0x67452301
	hasher.state[1] = 0xefcdab89
	hasher.state[2] = 0x98badcfe
	hasher.state[3] = 0x10325476
	hasher.count[0] = 0
	hasher.count[1] = 0
}

func (hasher *MD5Hasher) GetHash(data []uint8) []uint8 {
	hasher.updateMD5(data)
	digest := hasher.finalMD5()

	hasher.Reset()
	return digest[:]
}

func (hasher MD5Hasher) GetHashSize() uint32 {
	return HASH_SIZE_MD5
}

func CreateMD5Hasher() Hasher {
	hasher := MD5Hasher{}
	hasher.Reset()
	return &hasher
}