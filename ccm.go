package cryptoutils

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
)

// SealCCM implements RFC 3610 with an explicit nonce for interoperability.
// nonce must have 7..13 bytes and be unique per key. tagSize is even, 4..16.
// Unlike EncryptAEAD, its result does not include the nonce.
func SealCCM(algorithm string, data, key, nonce, aad []byte, tagSize int) ([]byte, error) {
	b, err := ccmCipher(algorithm, key, nonce, tagSize, len(data))
	if err != nil {
		return nil, err
	}
	tag := ccmMAC(b, data, nonce, aad, tagSize)
	out := make([]byte, len(data)+tagSize)
	ccmCTR(b, out[:len(data)], data, nonce, 1)
	var zero [16]byte
	var mask [16]byte
	ccmCTR(b, mask[:], zero[:], nonce, 0)
	for i := 0; i < tagSize; i++ {
		out[len(data)+i] = tag[i] ^ mask[i]
	}
	return out, nil
}

// OpenCCM authenticates ciphertext and returns no plaintext on failure.
func OpenCCM(algorithm string, data, key, nonce, aad []byte, tagSize int) ([]byte, error) {
	if tagSize < 4 || tagSize > 16 || tagSize%2 != 0 || len(data) < tagSize {
		return nil, fmt.Errorf("cryptoutils: invalid CCM ciphertext or tag size")
	}
	n := len(data) - tagSize
	b, err := ccmCipher(algorithm, key, nonce, tagSize, n)
	if err != nil {
		return nil, err
	}
	out := make([]byte, n)
	ccmCTR(b, out, data[:n], nonce, 1)
	tag := ccmMAC(b, out, nonce, aad, tagSize)
	var zero, mask [16]byte
	ccmCTR(b, mask[:], zero[:], nonce, 0)
	for i := 0; i < tagSize; i++ {
		tag[i] ^= mask[i]
	}
	if subtle.ConstantTimeCompare(tag[:tagSize], data[n:]) != 1 {
		for i := range out {
			out[i] = 0
		}
		return nil, fmt.Errorf("cryptoutils: CCM authentication failed")
	}
	return out, nil
}
func ccmCipher(algorithm string, key, nonce []byte, tagSize, n int) (cipher.Block, error) {
	if len(nonce) < 7 || len(nonce) > 13 || tagSize < 4 || tagSize > 16 || tagSize%2 != 0 {
		return nil, fmt.Errorf("cryptoutils: invalid CCM nonce or tag size")
	}
	l := 15 - len(nonce)
	if l < 8 && uint64(n) >= (uint64(1)<<uint(8*l)) {
		return nil, fmt.Errorf("cryptoutils: CCM message too long for nonce")
	}
	b, err := NewBlockCipher(algorithm, key)
	if err != nil {
		return nil, err
	}
	if b.BlockSize() != 16 {
		return nil, fmt.Errorf("cryptoutils: CCM needs a 16-byte block cipher")
	}
	return b, nil
}
func putCCMLength(dst []byte, n uint64) {
	for i := len(dst) - 1; i >= 0; i-- {
		dst[i] = byte(n)
		n >>= 8
	}
}
func ccmMAC(b cipher.Block, data, nonce, aad []byte, tagSize int) [16]byte {
	var state, block [16]byte
	l := 15 - len(nonce)
	block[0] = byte(((tagSize-2)/2)<<3 | (l - 1))
	if len(aad) > 0 {
		block[0] |= 0x40
	}
	copy(block[1:], nonce)
	putCCMLength(block[16-l:], uint64(len(data)))
	b.Encrypt(state[:], block[:])
	absorb := func(in []byte) {
		for len(in) > 0 {
			block = [16]byte{}
			n := copy(block[:], in)
			for i := range block {
				block[i] ^= state[i]
			}
			b.Encrypt(state[:], block[:])
			in = in[n:]
		}
	}
	if len(aad) > 0 {
		var prefix [10]byte
		var size int
		switch {
		case uint64(len(aad)) < 0xff00:
			binary.BigEndian.PutUint16(prefix[:], uint16(len(aad)))
			size = 2
		case uint64(len(aad)) <= 0xffffffff:
			prefix[0] = 0xff
			prefix[1] = 0xfe
			binary.BigEndian.PutUint32(prefix[2:], uint32(len(aad)))
			size = 6
		default:
			prefix[0] = 0xff
			prefix[1] = 0xff
			binary.BigEndian.PutUint64(prefix[2:], uint64(len(aad)))
			size = 10
		}
		block = [16]byte{}
		copy(block[:], prefix[:size])
		n := copy(block[size:], aad)
		for i := range block {
			block[i] ^= state[i]
		}
		b.Encrypt(state[:], block[:])
		absorb(aad[n:])
	}
	absorb(data)
	return state
}
func ccmCTR(b cipher.Block, dst, src, nonce []byte, counter uint64) {
	var block, stream [16]byte
	l := 15 - len(nonce)
	block[0] = byte(l - 1)
	copy(block[1:], nonce)
	for len(src) > 0 {
		putCCMLength(block[16-l:], counter)
		counter++
		b.Encrypt(stream[:], block[:])
		n := len(src)
		if n > 16 {
			n = 16
		}
		for i := 0; i < n; i++ {
			dst[i] = src[i] ^ stream[i]
		}
		dst = dst[n:]
		src = src[n:]
	}
}
