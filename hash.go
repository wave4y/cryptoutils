package cryptoutils

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"

	"golang.org/x/crypto/md4"
)

func (p *CryptoData) Md4() *CryptoData {
	p.checkFirst()
	hash := md4.New()
	hash.Write(p.data)
	dst := hash.Sum(nil)
	p.data = []byte(hex.EncodeToString(dst))
	return p
}

func (p *CryptoData) Md5() *CryptoData {
	p.checkFirst()
	hash := md5.New()
	hash.Write(p.data)
	dst := hash.Sum(nil)
	p.data = []byte(hex.EncodeToString(dst))
	return p
}

func (p *CryptoData) Sha1() *CryptoData {
	p.checkFirst()

	hash := sha1.New()
	hash.Write(p.data)
	dst := hash.Sum(nil)
	p.data = []byte(hex.EncodeToString(dst))
	return p
}

func (p *CryptoData) Sha256() *CryptoData {
	p.checkFirst()
	hash := sha256.New()
	hash.Write(p.data)
	dst := hash.Sum(nil)
	p.data = []byte(hex.EncodeToString(dst))
	return p
}

func (p *CryptoData) Sha512() *CryptoData {
	p.checkFirst()
	hash := sha512.New()
	hash.Write(p.data)
	dst := hash.Sum(nil)
	p.data = []byte(hex.EncodeToString(dst))
	return p
}

func (p *CryptoData) Hash(tool string) *CryptoData {
	p.checkFirst()
	var hash hash.Hash
	switch tool {
	case "md4":
		hash = md4.New()
	case "md5":
		hash = md5.New()
	case "sha1":
		hash = sha1.New()
	case "sha256":
		hash = sha256.New()
	case "sha512":
		hash = sha512.New()
	}

	hash.Write(p.data)
	dst := hash.Sum(nil)
	p.data = []byte(hex.EncodeToString(dst))
	return p
}
