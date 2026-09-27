package sm4

import (
	"crypto/cipher"
	"strconv"
)

// BlockSize The SM4 block size in bytes.
const BlockSize = 16

// KeySizeError key error
type KeySizeError int

func (k KeySizeError) Error() string {
	return "sm4: invalid key size " + strconv.Itoa(int(k))
}

// sm4Cipher is an instance of SM4 encryption.
type sm4Cipher struct {
	subkeys [32]uint32
}

// NewCipher creates and returns a new cipher.Block.
func NewCipher(key []byte) (cipher.Block, error) {
	if len(key) != 16 {
		return nil, KeySizeError(len(key))
	}

	c := new(sm4Cipher)
	c.generateSubkeys(key)
	return c, nil
}

func (c *sm4Cipher) BlockSize() int {
	return BlockSize
}

func (c *sm4Cipher) Encrypt(dst, src []byte) {
	checkBlockBuffers(dst, src)
	encryptBlock(c.subkeys[:], dst, src)
}

func (c *sm4Cipher) Decrypt(dst, src []byte) {
	checkBlockBuffers(dst, src)
	decryptBlock(c.subkeys[:], dst, src)
}

func checkBlockBuffers(dst, src []byte) {
	if len(src) < BlockSize {
		panic("sm4: input not full block")
	}
	if len(dst) < BlockSize {
		panic("sm4: output not full block")
	}
	if &dst[0] == &src[0] {
		return
	}
	// Only the first block is used. Equal starts are valid in-place operation;
	// otherwise either start inside the other block means partial overlap.
	for i := 1; i < BlockSize; i++ {
		if &dst[0] == &src[i] || &src[0] == &dst[i] {
			panic("sm4: invalid buffer overlap")
		}
	}
}
