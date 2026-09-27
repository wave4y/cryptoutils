package symmetric

import (
	"crypto/subtle"
	"fmt"

	"golang.org/x/crypto/poly1305"
)

// CMAC implements NIST SP 800-38B for 64- or 128-bit block ciphers.
func CMAC(algorithm string, data, key []byte) ([]byte, error) {
	b, err := NewBlockCipher(algorithm, key)
	if err != nil {
		return nil, err
	}
	bs := b.BlockSize()
	if bs != 8 && bs != 16 {
		return nil, fmt.Errorf("cryptoutils: unsupported CMAC block size")
	}
	k1 := make([]byte, bs)
	b.Encrypt(k1, k1)
	cmacDouble(k1)
	k2 := cloneBytes(k1)
	cmacDouble(k2)
	state := make([]byte, bs)
	for len(data) > bs {
		for i := 0; i < bs; i++ {
			state[i] ^= data[i]
		}
		b.Encrypt(state, state)
		data = data[bs:]
	}
	last := make([]byte, bs)
	copy(last, data)
	subkey := k1
	if len(data) != bs {
		last[len(data)] = 0x80
		subkey = k2
	}
	for i := 0; i < bs; i++ {
		state[i] ^= last[i] ^ subkey[i]
	}
	b.Encrypt(state, state)
	return state, nil
}

func cmacDouble(b []byte) {
	carry := b[0] >> 7
	for i := 0; i < len(b)-1; i++ {
		b[i] = b[i]<<1 | b[i+1]>>7
	}
	b[len(b)-1] <<= 1
	rb := byte(0x87)
	if len(b) == 8 {
		rb = 0x1b
	}
	b[len(b)-1] ^= rb * (carry & 1)
}

func VerifyCMAC(algorithm string, data, key, tag []byte) (bool, error) {
	expected, err := CMAC(algorithm, data, key)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(expected, tag) == 1, nil
}

// Poly1305 computes a raw 16-byte one-time authenticator. Each 32-byte key MUST
// be used for only one message. Prefer ChaCha20-Poly1305 for message encryption.
func Poly1305(data, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("cryptoutils: Poly1305 requires a 32-byte one-time key")
	}
	var k [32]byte
	var tag [16]byte
	copy(k[:], key)
	poly1305.Sum(&tag, data, &k)
	return tag[:], nil
}

func VerifyPoly1305(data, key, tag []byte) (bool, error) {
	expected, err := Poly1305(data, key)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(expected, tag) == 1, nil
}
