package utils

import "www.gitlablow.com/wave4y/cryptoutils"

// PKCS7Padding delegates to the root implementation.
func PKCS7Padding(src []byte, blockSize int) ([]byte, error) {
	return cryptoutils.PKCS7Padding(src, blockSize)
}

// PKCS7UnPadding delegates to the root implementation.
func PKCS7UnPadding(src []byte, blockSize int) ([]byte, error) {
	return cryptoutils.PKCS7UnPadding(src, blockSize)
}

// PKCS5Padding retains the historical wrapper.
// Deprecated: use PKCS7Padding, which returns validation errors.
func PKCS5Padding(src []byte, blockSize int) []byte {
	return cryptoutils.PKCS5Padding(src, blockSize)
}

// PKCS5UnPadding retains the historical wrapper for 8-byte blocks.
// Deprecated: use PKCS7UnPadding with an explicit block size.
func PKCS5UnPadding(src []byte) ([]byte, error) {
	return cryptoutils.PKCS5UnPadding(src)
}
