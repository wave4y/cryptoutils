package cryptoutils

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
)

func encrypt(src []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	src = padding(src, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, key)
	blockMode.CryptBlocks(src, src)
	return src, nil
}

func aaaa() {
	d := []byte("hello world")
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	x1, err := encrypt(d, key)
	if err != nil {
		return
	}
	fmt.Println(string(x1))
}
