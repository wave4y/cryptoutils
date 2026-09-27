package cryptoutils

import (
	"encoding/hex"
	"github.com/wave4y/cryptoutils/zuc"
)

// CryptZUC encrypts or decrypts with an explicit unique IV. It does not authenticate.
func CryptZUC(data, key, iv []byte) ([]byte, error) { return zuc.Crypt(data, key, iv) }
func ZUCMAC(data, key, iv []byte, tagSize int) ([]byte, error) {
	return zuc.MAC(data, key, iv, tagSize)
}
func VerifyZUCMAC(data, key, iv, tag []byte) (bool, error) { return zuc.VerifyMAC(data, key, iv, tag) }
func (p *CryptoData) ZUCEncrypt(iv []byte) *CryptoData {
	if p.err != nil {
		return p
	}
	out, err := CryptZUC(p.data, p.key, iv)
	if err != nil {
		return p.fail(err)
	}
	p.data = out
	return p
}
func (p *CryptoData) ZUCDecrypt(iv []byte) *CryptoData { return p.ZUCEncrypt(iv) }

// ZUCMAC stores a hexadecimal authentication tag, like other MAC chain methods.
func (p *CryptoData) ZUCMAC(iv []byte, tagSize int) *CryptoData {
	if p.err != nil {
		return p
	}
	out, err := ZUCMAC(p.data, p.key, iv, tagSize)
	if err != nil {
		return p.fail(err)
	}
	p.data = []byte(hex.EncodeToString(out))
	return p
}
