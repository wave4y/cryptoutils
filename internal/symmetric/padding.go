package symmetric

import (
	"crypto/subtle"
	"errors"
	"fmt"
)

// PKCS7Padding returns a padded copy of src. blockSize must be between 1 and
// 255 bytes. Empty input and input already aligned to a block receive a full
// block of padding.
func PKCS7Padding(src []byte, blockSize int) ([]byte, error) {
	if blockSize < 1 || blockSize > 255 {
		return nil, fmt.Errorf("cryptoutils: invalid padding block size %d", blockSize)
	}
	padLen := blockSize - len(src)%blockSize
	if len(src) > int(^uint(0)>>1)-padLen {
		return nil, errors.New("cryptoutils: padded data is too large")
	}
	out := make([]byte, len(src)+padLen)
	copy(out, src)
	for i := len(src); i < len(out); i++ {
		out[i] = byte(padLen)
	}
	return out, nil
}

// PKCS7UnPadding validates every padding byte and returns an unpadded copy.
// src must contain a nonempty whole number of blocks. This function only checks
// padding, not authenticity; authenticate ciphertext before decrypting it.
func PKCS7UnPadding(src []byte, blockSize int) ([]byte, error) {
	if blockSize < 1 || blockSize > 255 {
		return nil, fmt.Errorf("cryptoutils: invalid padding block size %d", blockSize)
	}
	if len(src) == 0 || len(src)%blockSize != 0 {
		return nil, errors.New("cryptoutils: invalid PKCS#7 padding")
	}
	padLen := int(src[len(src)-1])
	valid := subtle.ConstantTimeLessOrEq(1, padLen) & subtle.ConstantTimeLessOrEq(padLen, blockSize)
	// Inspect the entire final block regardless of the claimed padding length.
	for i := 1; i <= blockSize; i++ {
		isPadding := subtle.ConstantTimeLessOrEq(i, padLen)
		matches := subtle.ConstantTimeByteEq(src[len(src)-i], byte(padLen))
		valid &= subtle.ConstantTimeSelect(isPadding, matches, 1)
	}
	if valid != 1 {
		return nil, errors.New("cryptoutils: invalid PKCS#7 padding")
	}
	out := make([]byte, len(src)-padLen)
	copy(out, src[:len(src)-padLen])
	return out, nil
}

// PKCS5Padding returns a padded copy, or nil when blockSize is not 8.
//
// Deprecated: use PKCS7Padding for an explicit error and a configurable block
// size. PKCS#5 padding is defined only for 8 byte blocks.
func PKCS5Padding(src []byte, blockSize int) []byte {
	if blockSize != 8 {
		return nil
	}
	out, _ := PKCS7Padding(src, blockSize)
	return out
}

// PKCS5UnPadding validates and removes padding for 8 byte blocks.
//
// Deprecated: use PKCS7UnPadding and specify the cipher's block size.
func PKCS5UnPadding(src []byte) ([]byte, error) {
	return PKCS7UnPadding(src, 8)
}
