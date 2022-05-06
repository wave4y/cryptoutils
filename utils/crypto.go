package utils

import (
	"crypto/cipher"
	"crypto/des"
	"errors"
)

var errNone = errors.New("key not correct")

func validKey(key []byte) bool {
	k := len(key)
	switch k {
	default:
		return false
	case 16, 24, 32:
		return true
	}
}

func (p *CryptoData) DesCBCEncrypt() *CryptoData {
	p.checkFirst()
	if len(p.key) != 8 {
		checkErr(errNone, "")
	}

	block, err := des.NewCipher(p.key)
	checkErr(err, "des")

	blockSize := block.BlockSize()
	nsrc := padding(p.data, blockSize)
	//加密模式；CBC（密码分组链接模式）
	blockMode := cipher.NewCBCEncrypter(block, p.key[:blockSize])

	dst := make([]byte, len(nsrc))

	blockMode.CryptBlocks(dst, nsrc)

	p.data = dst
	return p
}

func (p *CryptoData) DesDecrypt() *CryptoData {
	if len(p.key) != 8 {
		checkErr(errNone, "")
	}

	block, err := des.NewCipher(p.key)
	checkErr(err, "des")

	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, p.key[:blockSize])
	dst := make([]byte, len(p.data))

	blockMode.CryptBlocks(dst, p.data)

	//去掉填充串
	dst = unPadding(dst)
	p.data = dst

	return p
}
