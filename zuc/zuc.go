// Package zuc implements ZUC-128 and ZUC-256 and their integrity algorithms.
// These portable implementations use table lookups and are not constant-time.
// A key/IV pair must never be reused, including between encryption and MAC.
package zuc

import (
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/bits"
	"unsafe"
)

// Cipher is a stateful cipher.Stream. It must not be used concurrently.
type Cipher struct {
	s      [16]uint32
	r1, r2 uint32
	buf    [4]byte
	used   int
}

// NewCipher selects ZUC-128 (16-byte key and IV) or ZUC-256 (32-byte key,
// 23-byte packed IV). Encryption alone does not authenticate the message.
func NewCipher(key, iv []byte) (*Cipher, error) { return newCipher(key, iv, 0) }
func newCipher(key, iv []byte, tagSize int) (*Cipher, error) {
	c := &Cipher{used: 4}
	switch len(key) {
	case 16:
		if len(iv) != 16 || (tagSize != 0 && tagSize != 4) {
			return nil, errors.New("zuc: ZUC-128 requires a 16-byte IV and 4-byte MAC")
		}
		d := [16]uint32{0x44d7, 0x26bc, 0x626b, 0x135e, 0x5789, 0x35e2, 0x7135, 0x09af, 0x4d78, 0x2f13, 0x6bc4, 0x1af1, 0x5e26, 0x3c4d, 0x789a, 0x47ac}
		for i := range c.s {
			c.s[i] = uint32(key[i])<<23 | d[i]<<8 | uint32(iv[i])
		}
	case 32:
		if len(iv) != 23 {
			return nil, errors.New("zuc: ZUC-256 requires a 23-byte packed IV")
		}
		if tagSize != 0 && tagSize != 4 && tagSize != 8 && tagSize != 16 {
			return nil, errors.New("zuc: invalid ZUC-256 tag size")
		}
		d := [16]byte{0x22, 0x2f, 0x24, 0x2a, 0x6d, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x52, 0x10, 0x30}
		if tagSize == 4 || tagSize == 16 {
			d[2] |= 1
		}
		if tagSize == 8 || tagSize == 16 {
			d[0] |= 1
		}
		v := [8]byte{iv[17] >> 2, (iv[17]&3)<<4 | iv[18]>>4, (iv[18]&15)<<2 | iv[19]>>6, iv[19] & 63, iv[20] >> 2, (iv[20]&3)<<4 | iv[21]>>4, (iv[21]&15)<<2 | iv[22]>>6, iv[22] & 63}
		pack := func(a, b, e, f byte) uint32 { return uint32(a)<<23 | uint32(b)<<16 | uint32(e)<<8 | uint32(f) }
		for i := 0; i < 5; i++ {
			c.s[i] = pack(key[i], d[i], key[21+i], key[16+i])
		}
		c.s[5] = pack(iv[0], d[5]|v[0], key[5], key[26])
		c.s[6] = pack(iv[1], d[6]|v[1], key[6], key[27])
		c.s[7] = pack(iv[10], d[7]|v[2], key[7], iv[2])
		c.s[8] = pack(key[8], d[8]|v[3], iv[3], iv[11])
		c.s[9] = pack(key[9], d[9]|v[4], iv[12], iv[4])
		c.s[10] = pack(iv[5], d[10]|v[5], key[10], key[28])
		c.s[11] = pack(key[11], d[11]|v[6], iv[6], iv[13])
		c.s[12] = pack(key[12], d[12]|v[7], iv[7], iv[14])
		c.s[13] = pack(key[13], d[13], iv[15], iv[8])
		c.s[14] = pack(key[14], d[14]|key[31]>>4, iv[16], iv[9])
		c.s[15] = pack(key[15], d[15]|key[31]&15, key[30], key[29])
	default:
		return nil, errors.New("zuc: key must contain 16 or 32 bytes")
	}
	for i := 0; i < 32; i++ {
		w, _ := c.f()
		c.advance(w >> 1)
	}
	c.f()
	c.advance(0)
	return c, nil
}
func (c *Cipher) advance(u uint32) {
	v := uint64(c.s[0]) + (uint64(c.s[0]) << 8) + (uint64(c.s[4]) << 20) + (uint64(c.s[10]) << 21) + (uint64(c.s[13]) << 17) + (uint64(c.s[15]) << 15) + uint64(u)
	v = (v & 0x7fffffff) + (v >> 31)
	v = (v & 0x7fffffff) + (v >> 31)
	if v == 0 {
		v = 0x7fffffff
	}
	copy(c.s[:15], c.s[1:])
	c.s[15] = uint32(v)
}
func substitute(x uint32) uint32 {
	return uint32(s0[x>>24])<<24 | uint32(s1[(x>>16)&255])<<16 | uint32(s0[(x>>8)&255])<<8 | uint32(s1[x&255])
}
func (c *Cipher) f() (uint32, uint32) {
	x0 := (c.s[15]&0x7fff8000)<<1 | c.s[14]&0xffff
	x1 := c.s[11]<<16 | c.s[9]>>15
	x2 := c.s[7]<<16 | c.s[5]>>15
	x3 := c.s[2]<<16 | c.s[0]>>15
	w := (x0 ^ c.r1) + c.r2
	w1, w2 := c.r1+x1, c.r2^x2
	u, v := w1<<16|w2>>16, w2<<16|w1>>16
	u = u ^ bits.RotateLeft32(u, 2) ^ bits.RotateLeft32(u, 10) ^ bits.RotateLeft32(u, 18) ^ bits.RotateLeft32(u, 24)
	v = v ^ bits.RotateLeft32(v, 8) ^ bits.RotateLeft32(v, 14) ^ bits.RotateLeft32(v, 22) ^ bits.RotateLeft32(v, 30)
	c.r1, c.r2 = substitute(u), substitute(v)
	return w, x3
}
func (c *Cipher) word() uint32 { w, x3 := c.f(); c.advance(0); return w ^ x3 }

// XORKeyStream implements cipher.Stream, supporting exact in-place operation.
func (c *Cipher) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("zuc: output smaller than input")
	}
	if len(src) > 0 && &dst[0] != &src[0] {
		a, b := uintptr(unsafe.Pointer(&dst[0])), uintptr(unsafe.Pointer(&src[0]))
		if a <= b+uintptr(len(src)-1) && b <= a+uintptr(len(src)-1) {
			panic("zuc: invalid buffer overlap")
		}
	}
	for i, b := range src {
		if c.used == 4 {
			binary.BigEndian.PutUint32(c.buf[:], c.word())
			c.used = 0
		}
		dst[i] = b ^ c.buf[c.used]
		c.used++
	}
}

// Crypt encrypts or decrypts data without modifying the input.
func Crypt(data, key, iv []byte) ([]byte, error) {
	c, err := NewCipher(key, iv)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	c.XORKeyStream(out, data)
	return out, nil
}

// MAC authenticates all input bits. tagSize is in bytes: 4 for ZUC-128;
// 4, 8 or 16 for ZUC-256. The key/IV must be unique for each message.
func MAC(data, key, iv []byte, tagSize int) ([]byte, error) {
	if len(data) > int(^uint(0)>>1)/8 {
		return nil, errors.New("zuc: message too large")
	}
	return MACBits(data, len(data)*8, key, iv, tagSize)
}

// MACBits authenticates the first bitLen bits, most significant bit first.
func MACBits(data []byte, bitLen int, key, iv []byte, tagSize int) ([]byte, error) {
	if bitLen < 0 || bitLen/8 > len(data) || (bitLen/8 == len(data) && bitLen%8 != 0) {
		return nil, errors.New("zuc: invalid bit length")
	}
	if tagSize == 0 {
		return nil, errors.New("zuc: invalid tag size")
	}
	c, err := newCipher(key, iv, tagSize)
	if err != nil {
		return nil, err
	}
	n := tagSize / 4
	t := make([]uint32, n)
	window := make([]uint32, n)
	if len(key) == 32 {
		for j := range t {
			t[j] = c.word()
		}
	}
	for j := range window {
		window[j] = c.word()
	}
	var next uint32
	for i := 0; i < bitLen; i++ {
		if i%32 == 0 {
			next = c.word()
		}
		mask := uint32(0) - uint32((data[i/8]>>uint(7-i%8))&1)
		for j := range t {
			t[j] ^= window[j] & mask
		}
		for j := 0; j < n-1; j++ {
			window[j] = window[j]<<1 | window[j+1]>>31
		}
		window[n-1] = window[n-1]<<1 | next>>31
		next <<= 1
	}
	for j := range t {
		t[j] ^= window[j]
	}
	if len(key) == 16 {
		t[0] ^= c.word()
	}
	out := make([]byte, tagSize)
	for j, v := range t {
		binary.BigEndian.PutUint32(out[4*j:], v)
	}
	return out, nil
}
func VerifyMAC(data, key, iv, tag []byte) (bool, error) {
	expected, err := MAC(data, key, iv, len(tag))
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(expected, tag) == 1, nil
}

// Standard ZUC substitution tables; see ETSI/SAGE ZUC specification, section 3.
func table(s string) [256]byte {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 256 {
		panic("zuc: invalid constant")
	}
	var out [256]byte
	copy(out[:], b)
	return out
}

var s0 = table("3e725b47cae0003304d1549809b96dcb" +
	"7b1bf932af9d6aa5b82dfc1d08530390" + "4d4e8499e4ced991ddb685488b296eac" + "cdc1f81e734369c6b5bdfd396320d438" +
	"767db2a7cfed57c5f32cbb142106559b" + "e3ef5e314f7f5aa40d8251495fba581c" + "4a16d517a892241f8cffd8ae2e01d3ad" + "3b4bda46ebc9de9a8f87d73a806f2fc8" +
	"b1b437f70a2213287ccc3c89c7c39656" + "07bf7ef00b2b975235417961a64c10fe" + "bc2695888ab0a3fbc01894f2e1e5e95d" + "d0dc1166645cec59427512f5749caa23" +
	"0e86abbe2a02e767e644a26cc2939ff1" + "f6fa36d250689e6271153dd640c4e20f" + "8e83776b25053f0c30ea70b7a1e8a965" + "8d271adb81b3a0f4457a19dfee783460")
var s1 = table("55c263713bc847869f3cda5b29aafd77" +
	"8cc5940ca61a1300e3a8167240f9f842" + "4426689681d9453e1076c6a78b3943e1" + "3ab5562ac06db3052266bfdc0bfa6248" +
	"dd20110636c9c1cff62752bb69f5d487" + "7f844cd29c57a4bc4f9adffed68d7aeb" + "2b53d85ca11417fb23d57d3067730809" + "eeb7703f61b2198e4ee54b938f5ddba9" +
	"adf1ae2ecb0dfcf42d466e1d97e8d1e9" + "4d37a5755e839eab829db91ce0cd4989" + "01b6bd5824a25f387899159050b895e4" + "d091c7ceed0fb46fa0ccf0024a79c3de" +
	"a3efea51e66b18ec1b2c80f774e7ff21" + "5a6a541e41319235c433070aba7e0e34" + "88b1987cf33d606c7bcad31f32650428" + "64be859b2f598ad7b025acaf1203e2f2")
