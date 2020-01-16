package hasher

type Hasher interface {
	/* */
	GetHash([]uint8) []uint8

	/**/
	GetHashSize() uint32
	/**/
	Reset()
}

///* Private interface for creating Extender */
//type PrivateHasher interface {
//	/* */
//	Update(data []uint8)
//
//	/* Transform */
//	Transform([]uint8)
//
//	ChangeStatus(*PrivateHasher)
//
//	/**/
//	Final() []uint8
//}

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

func f(x uint32, y uint32, z uint32) uint32 {
	return ((x) & (y)) | ((^x) & (z))
}
func g(x uint32, y uint32, z uint32) uint32 {
	return ((x) & (z)) | ((y) & (^z))
}
func h(x uint32, y uint32, z uint32) uint32 {
	return (x) ^ (y) ^ (z)
}
func i(x uint32, y uint32, z uint32) uint32 {
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

func ff(a *uint32, b uint32, c uint32, d uint32, x uint32, s uint8, ac uint32) {
	transform(a, b, c, d, x, s, ac, f)
}

func gg(a *uint32, b uint32, c uint32, d uint32, x uint32, s uint8, ac uint32) {
	transform(a, b, c, d, x, s, ac, g)
}

func hh(a *uint32, b uint32, c uint32, d uint32, x uint32, s uint8, ac uint32) {
	transform(a, b, c, d, x, s, ac, h)
}

func ii(a *uint32, b uint32, c uint32, d uint32, x uint32, s uint8, ac uint32) {
	transform(a, b, c, d, x, s, ac, i)
}

func Encode(input []uint32) []uint8 {
	output := make([]uint8, len(input) * 4)
	for i, j := 0, 0; j < len(output); i, j = i + 1, j + 4 {
		output[j] = uint8(input[i] & 0xff)
		output[j+1] = uint8((input[i] >> 8) & 0xff)
		output[j+2] = uint8((input[i] >> 16) & 0xff)
		output[j+3] = uint8((input[i] >> 24) & 0xff)
	}
	return output
}

func Decode(input []uint8) []uint32 {
	output := make([]uint32, len(input) / 4)
	for i, j := 0, 0; j < len(input); i, j = i + 1, j + 4 {
		output[i] = uint32(input[j]) | (uint32(input[j+1]) << 8) |
					  (uint32(input[j+2]) << 16) | (uint32(input[j+3]) << 24)
	}
	return output
}

/* MD5 basic transformation. Transforms state based on block */
func (hasher *MD5Hasher) Transform(block []uint8) {
	var a,b,c,d = hasher.state[0], hasher.state[1], hasher.state[2], hasher.state[3]
	var x = Decode(block[:])

	/* Round 1 */
	ff(&a, b, c, d, x[ 0], S11, 0xd76aa478) /* 1 */
	ff(&d, a, b, c, x[ 1], S12, 0xe8c7b756) /* 2 */
	ff(&c, d, a, b, x[ 2], S13, 0x242070db) /* 3 */
	ff(&b, c, d, a, x[ 3], S14, 0xc1bdceee) /* 4 */
	ff(&a, b, c, d, x[ 4], S11, 0xf57c0faf) /* 5 */
	ff(&d, a, b, c, x[ 5], S12, 0x4787c62a) /* 6 */
	ff(&c, d, a, b, x[ 6], S13, 0xa8304613) /* 7 */
	ff(&b, c, d, a, x[ 7], S14, 0xfd469501) /* 8 */
	ff(&a, b, c, d, x[ 8], S11, 0x698098d8) /* 9 */
	ff(&d, a, b, c, x[ 9], S12, 0x8b44f7af) /* 10 */
	ff(&c, d, a, b, x[10], S13, 0xffff5bb1) /* 11 */
	ff(&b, c, d, a, x[11], S14, 0x895cd7be) /* 12 */
	ff(&a, b, c, d, x[12], S11, 0x6b901122) /* 13 */
	ff(&d, a, b, c, x[13], S12, 0xfd987193) /* 14 */
	ff(&c, d, a, b, x[14], S13, 0xa679438e) /* 15 */
	ff(&b, c, d, a, x[15], S14, 0x49b40821) /* 16 */

	/* Round 2 */
	gg(&a, b, c, d, x[ 1], S21, 0xf61e2562) /* 17 */
	gg(&d, a, b, c, x[ 6], S22, 0xc040b340) /* 18 */
	gg(&c, d, a, b, x[11], S23, 0x265e5a51) /* 19 */
	gg(&b, c, d, a, x[ 0], S24, 0xe9b6c7aa) /* 20 */
	gg(&a, b, c, d, x[ 5], S21, 0xd62f105d) /* 21 */
	gg(&d, a, b, c, x[10], S22, 0x2441453)  /* 22 */
	gg(&c, d, a, b, x[15], S23, 0xd8a1e681) /* 23 */
	gg(&b, c, d, a, x[ 4], S24, 0xe7d3fbc8) /* 24 */
	gg(&a, b, c, d, x[ 9], S21, 0x21e1cde6) /* 25 */
	gg(&d, a, b, c, x[14], S22, 0xc33707d6) /* 26 */
	gg(&c, d, a, b, x[ 3], S23, 0xf4d50d87) /* 27 */
	gg(&b, c, d, a, x[ 8], S24, 0x455a14ed) /* 28 */
	gg(&a, b, c, d, x[13], S21, 0xa9e3e905) /* 29 */
	gg(&d, a, b, c, x[ 2], S22, 0xfcefa3f8) /* 30 */
	gg(&c, d, a, b, x[ 7], S23, 0x676f02d9) /* 31 */
	gg(&b, c, d, a, x[12], S24, 0x8d2a4c8a) /* 32 */

	/* Round 3 */
	hh(&a, b, c, d, x[ 5], S31, 0xfffa3942) /* 33 */
	hh(&d, a, b, c, x[ 8], S32, 0x8771f681) /* 34 */
	hh(&c, d, a, b, x[11], S33, 0x6d9d6122) /* 35 */
	hh(&b, c, d, a, x[14], S34, 0xfde5380c) /* 36 */
	hh(&a, b, c, d, x[ 1], S31, 0xa4beea44) /* 37 */
	hh(&d, a, b, c, x[ 4], S32, 0x4bdecfa9) /* 38 */
	hh(&c, d, a, b, x[ 7], S33, 0xf6bb4b60) /* 39 */
	hh(&b, c, d, a, x[10], S34, 0xbebfbc70) /* 40 */
	hh(&a, b, c, d, x[13], S31, 0x289b7ec6) /* 41 */
	hh(&d, a, b, c, x[ 0], S32, 0xeaa127fa) /* 42 */
	hh(&c, d, a, b, x[ 3], S33, 0xd4ef3085) /* 43 */
	hh(&b, c, d, a, x[ 6], S34, 0x4881d05)  /* 44 */
	hh(&a, b, c, d, x[ 9], S31, 0xd9d4d039) /* 45 */
	hh(&d, a, b, c, x[12], S32, 0xe6db99e5) /* 46 */
	hh(&c, d, a, b, x[15], S33, 0x1fa27cf8) /* 47 */
	hh(&b, c, d, a, x[ 2], S34, 0xc4ac5665) /* 48 */

	/* Round 4 */
	ii(&a, b, c, d, x[ 0], S41, 0xf4292244) /* 49 */
	ii(&d, a, b, c, x[ 7], S42, 0x432aff97) /* 50 */
	ii(&c, d, a, b, x[14], S43, 0xab9423a7) /* 51 */
	ii(&b, c, d, a, x[ 5], S44, 0xfc93a039) /* 52 */
	ii(&a, b, c, d, x[12], S41, 0x655b59c3) /* 53 */
	ii(&d, a, b, c, x[ 3], S42, 0x8f0ccc92) /* 54 */
	ii(&c, d, a, b, x[10], S43, 0xffeff47d) /* 55 */
	ii(&b, c, d, a, x[ 1], S44, 0x85845dd1) /* 56 */
	ii(&a, b, c, d, x[ 8], S41, 0x6fa87e4f) /* 57 */
	ii(&d, a, b, c, x[15], S42, 0xfe2ce6e0) /* 58 */
	ii(&c, d, a, b, x[ 6], S43, 0xa3014314) /* 59 */
	ii(&b, c, d, a, x[13], S44, 0x4e0811a1) /* 60 */
	ii(&a, b, c, d, x[ 4], S41, 0xf7537e82) /* 61 */
	ii(&d, a, b, c, x[11], S42, 0xbd3af235) /* 62 */
	ii(&c, d, a, b, x[ 2], S43, 0x2ad7d2bb) /* 63 */
	ii(&b, c, d, a, x[ 9], S44, 0xeb86d391) /* 64 */

	hasher.state[0] += a
	hasher.state[1] += b
	hasher.state[2] += c
	hasher.state[3] += d
}

func (hasher *MD5Hasher) ChangeStatus(state []uint32, count []uint32){
	copy(hasher.state[:], state[:])
	copy(hasher.count[:], count[:])
}

func (hasher *MD5Hasher) Update(data []uint8) {
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
		hasher.Transform(hasher.buffer[:])
		for i:=partLen; i + 63 < inputLen; i += 64 {
			hasher.Transform(data[i:])
		}
		index = 0
	} else {
		i = 0
	}

	/* Buffer remaining input */
	copy(hasher.buffer[index:], data[i:])
}

func (hasher *MD5Hasher) Final() []uint8 {
	var index, padLen uint32
	var digest [HASH_SIZE_MD5]uint8
	bits := Encode(hasher.count[0:2])

	/* Pad out to 56 mod 64. */
	index = (hasher.count[0] >> 3) & 0x3f
	padLen = 56 - index
	if index >= 56 {
		padLen = 120 - index
	}
	hasher.Update(PADDING[0:padLen])

	/* Append length (before padding) */
	hasher.Update(bits[0:8])

	copy(digest[:], Encode(hasher.state[0:4]))
	return digest[:]
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
	hasher.Update(data)
	digest := hasher.Final()

	hasher.Reset()
	return digest[:]
}

func (hasher MD5Hasher) GetHashSize() uint32 {
	return HASH_SIZE_MD5
}


func CreateMD5Hasher() MD5Hasher {
	hasher := MD5Hasher{}
	hasher.Reset()
	return hasher
}

func CreateHasher() Hasher {
	hasher := MD5Hasher{}
	hasher.Reset()
	return &hasher
}