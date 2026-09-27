// Package idea implements the IDEA block cipher for protocol compatibility.
// IDEA is specified in ISO/IEC 18033-3. This portable implementation is not
// constant-time and must not be used where local timing attacks are in scope.
package idea

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
)

const BlockSize = 8

type block struct {
	keys    [52]uint16
	inverse [18]uint16
}

// NewCipher constructs IDEA with a 16-byte key.
func NewCipher(key []byte) (cipher.Block, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("idea: invalid key size %d", len(key))
	}
	c := new(block)
	for i := 0; i < 8; i++ {
		c.keys[i] = binary.BigEndian.Uint16(key[2*i:])
	}
	for i := 8; i < 52; i++ {
		switch i % 8 {
		case 6:
			c.keys[i] = c.keys[i-7]<<9 | c.keys[i-14]>>7
		case 7:
			c.keys[i] = c.keys[i-15]<<9 | c.keys[i-14]>>7
		default:
			c.keys[i] = c.keys[i-7]<<9 | c.keys[i-6]>>7
		}
	}
	for i := 0; i < 8; i++ {
		c.inverse[2*i] = inv(c.keys[6*i])
		c.inverse[2*i+1] = inv(c.keys[6*i+3])
	}
	c.inverse[16] = inv(c.keys[48])
	c.inverse[17] = inv(c.keys[51])
	return c, nil
}
func (*block) BlockSize() int { return BlockSize }
func check(dst, src []byte) {
	if len(src) < 8 || len(dst) < 8 {
		panic("idea: short block")
	}
	if &src[0] == &dst[0] {
		return
	}
	for i := 1; i < 8; i++ {
		if &src[0] == &dst[i] || &dst[0] == &src[i] {
			panic("idea: invalid buffer overlap")
		}
	}
}
func mul(a, b uint16) uint16 {
	x, y := uint64(a), uint64(b)
	if x == 0 {
		x = 65536
	}
	if y == 0 {
		y = 65536
	}
	return uint16(x * y % 65537)
}
func inv(a uint16) uint16 {
	x := int64(a)
	if x == 0 {
		x = 65536
	}
	t, newT, r, newR := int64(0), int64(1), int64(65537), x
	for newR != 0 {
		q := r / newR
		t, newT = newT, t-q*newT
		r, newR = newR, r-q*newR
	}
	if t < 0 {
		t += 65537
	}
	return uint16(t)
}
func read(src []byte) (uint16, uint16, uint16, uint16) {
	return binary.BigEndian.Uint16(src), binary.BigEndian.Uint16(src[2:]), binary.BigEndian.Uint16(src[4:]), binary.BigEndian.Uint16(src[6:])
}
func write(dst []byte, a, b, c, d uint16) {
	binary.BigEndian.PutUint16(dst, a)
	binary.BigEndian.PutUint16(dst[2:], b)
	binary.BigEndian.PutUint16(dst[4:], c)
	binary.BigEndian.PutUint16(dst[6:], d)
}
func (s *block) Encrypt(dst, src []byte) {
	check(dst, src)
	a, b, c, d := read(src)
	for r := 0; r < 8; r++ {
		k := s.keys[r*6:]
		a = mul(a, k[0])
		b += k[1]
		c += k[2]
		d = mul(d, k[3])
		e := mul(a^c, k[4])
		f := mul((b^d)+e, k[5])
		e += f
		a ^= f
		d ^= e
		b, c = c^f, b^e
	}
	write(dst, mul(a, s.keys[48]), c+s.keys[49], b+s.keys[50], mul(d, s.keys[51]))
}
func (s *block) Decrypt(dst, src []byte) {
	check(dst, src)
	a, c, b, d := read(src)
	a = mul(a, s.inverse[16])
	c -= s.keys[49]
	b -= s.keys[50]
	d = mul(d, s.inverse[17])
	for r := 7; r >= 0; r-- {
		k := s.keys[r*6:]
		e := mul(a^b, k[4])
		f := mul((c^d)+e, k[5])
		e += f
		a = mul(a^f, s.inverse[2*r])
		b, c = (c^e)-k[1], (b^f)-k[2]
		d = mul(d^e, s.inverse[2*r+1])
	}
	write(dst, a, b, c, d)
}
