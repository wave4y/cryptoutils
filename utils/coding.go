package utils

import (
	"encoding/base64"
	"encoding/hex"
)

func (p *CryptoData) Hex() *CryptoData {
	p.checkFirst()

	p.data = []byte(hex.EncodeToString(p.data))
	return p
}

func (p *CryptoData) Base64Encode() *CryptoData {
	p.checkFirst()
	p.data = []byte(base64.StdEncoding.EncodeToString(p.data))
	return p
}
func (p *CryptoData) Base64Decode() *CryptoData {
	p.checkFirst()
	var err error
	p.data, err = base64.StdEncoding.DecodeString(string(p.data))
	checkErr(err, "base64")
	return p
}
