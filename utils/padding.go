package utils

import (
	"bytes"
	"fmt"
)

func padding(src []byte, blockSize int) []byte {
	length := blockSize - len(src)%blockSize
	paddingStr := bytes.Repeat([]byte{byte(length)}, length)
	nsrc := append(src, paddingStr...)

	return nsrc
}

//去掉填充串
func unPadding(src []byte) []byte {
	//填充长度
	length := int(src[len(src)-1])
	src = src[:(len(src) - length)]

	return src
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// 去除PKCS5填充
func PKCS5UnPadding(origData []byte) ([]byte, error) {
	length := len(origData)
	unpadding := int(origData[length-1])

	if length < unpadding {
		return nil, fmt.Errorf("invalid unpadding length")
	}
	return origData[:(length - unpadding)], nil
}
