package cryptoutils

import (
	"github.com/wave4y/cryptoutils/internal/digest"
)

// MaxSHAKEOutput bounds a single XOF allocation to one MiB.
const MaxSHAKEOutput = digest.MaxSHAKEOutput

// Md4 computes a hexadecimal MD4 digest.
//
// Deprecated: MD4 is for legacy compatibility, not security-sensitive uses.
func (p *CryptoData) Md4() *CryptoData { return p.Hash("md4") }

// Md5 computes a hexadecimal MD5 digest.
//
// Deprecated: MD5 is for legacy compatibility, not security-sensitive uses.
func (p *CryptoData) Md5() *CryptoData { return p.Hash("md5") }

// Sha1 computes a hexadecimal SHA-1 digest.
//
// Deprecated: SHA-1 is for legacy compatibility, not collision-resistant uses.
func (p *CryptoData) Sha1() *CryptoData { return p.Hash("sha1") }

// Sha256 computes a hexadecimal SHA-256 digest.
func (p *CryptoData) Sha256() *CryptoData { return p.Hash("sha256") }

// Sha512 computes a hexadecimal SHA-512 digest.
func (p *CryptoData) Sha512() *CryptoData { return p.Hash("sha512") }

// Sm3 computes a hexadecimal SM3 digest.
func (p *CryptoData) Sm3() *CryptoData { return p.Hash("sm3") }

func (p *CryptoData) Sha224() *CryptoData { return p.Hash("sha224") }

func (p *CryptoData) Sha384() *CryptoData { return p.Hash("sha384") }

func (p *CryptoData) Sha512224() *CryptoData { return p.Hash("sha512/224") }

func (p *CryptoData) Sha512256() *CryptoData { return p.Hash("sha512/256") }

func (p *CryptoData) Sha3_224() *CryptoData { return p.Hash("sha3-224") }

func (p *CryptoData) Sha3_256() *CryptoData { return p.Hash("sha3-256") }

func (p *CryptoData) Sha3_384() *CryptoData { return p.Hash("sha3-384") }

func (p *CryptoData) Sha3_512() *CryptoData { return p.Hash("sha3-512") }

func (p *CryptoData) Keccak256() *CryptoData { return p.Hash("keccak256") }

func (p *CryptoData) Keccak512() *CryptoData { return p.Hash("keccak512") }

func (p *CryptoData) Blake2b256() *CryptoData { return p.Hash("blake2b256") }

func (p *CryptoData) Blake2b384() *CryptoData { return p.Hash("blake2b384") }

func (p *CryptoData) Blake2b512() *CryptoData { return p.Hash("blake2b512") }

func (p *CryptoData) Blake2s256() *CryptoData { return p.Hash("blake2s256") }

func (p *CryptoData) Ripemd160() *CryptoData { return p.Hash("ripemd160") }

// Hash computes a lowercase hexadecimal digest. Names are case-insensitive;
// Hyphens, underscores and slashes in names are optional. Variable-length SHAKE
// uses the separate Shake128/Shake256 methods with an explicit output length.
func (p *CryptoData) Hash(tool string) *CryptoData {
	return p.HashBytes(tool).Hex()
}

// HashBytes computes raw digest bytes, for example before Base64Encode.
func (p *CryptoData) HashBytes(tool string) *CryptoData {
	if p.err != nil {
		return p
	}
	h, err := digest.New(tool)
	if err != nil {
		return p.fail(err)
	}
	_, _ = h.Write(p.data)
	p.data = h.Sum(nil)
	return p
}

// HMAC returns a raw HMAC tag using a supported fixed-length hash.
func HMAC(data, key []byte, algorithm string) ([]byte, error) {
	return digest.HMAC(data, key, algorithm)
}

// VerifyHMAC compares the complete raw tag in constant time. A mismatched tag
// returns false, nil; an unsupported hash returns an error.
func VerifyHMAC(data, key, tag []byte, algorithm string) (bool, error) {
	return digest.VerifyHMAC(data, key, tag, algorithm)
}

// HMAC computes a lowercase hexadecimal tag for the current data.
func (p *CryptoData) HMAC(key []byte, algorithm string) *CryptoData {
	return p.HMACBytes(key, algorithm).Hex()
}

// HMACBytes computes a raw tag for the current data.
func (p *CryptoData) HMACBytes(key []byte, algorithm string) *CryptoData {
	if p.err != nil {
		return p
	}
	tag, err := HMAC(p.data, key, algorithm)
	if err != nil {
		return p.fail(err)
	}
	p.data = tag
	return p
}

// SHAKE128 returns length raw bytes from the SHAKE128 extensible-output function.
func SHAKE128(data []byte, length int) ([]byte, error) { return digest.SHAKE128(data, length) }

// SHAKE256 returns length raw bytes from the SHAKE256 extensible-output function.
func SHAKE256(data []byte, length int) ([]byte, error) { return digest.SHAKE256(data, length) }

func (p *CryptoData) Shake128(length int) *CryptoData { return p.Shake128Bytes(length).Hex() }

func (p *CryptoData) Shake256(length int) *CryptoData { return p.Shake256Bytes(length).Hex() }

func (p *CryptoData) Shake128Bytes(length int) *CryptoData {
	return p.applySHAKE(length, SHAKE128)
}

func (p *CryptoData) Shake256Bytes(length int) *CryptoData {
	return p.applySHAKE(length, SHAKE256)
}

func (p *CryptoData) applySHAKE(length int, f func([]byte, int) ([]byte, error)) *CryptoData {
	if p.err != nil {
		return p
	}
	out, err := f(p.data, length)
	if err != nil {
		return p.fail(err)
	}
	p.data = out
	return p
}

// HMACSHA256 returns the raw authentication tag for data using key.
func HMACSHA256(data, key []byte) []byte { return digest.HMACSHA256(data, key) }

// VerifyHMACSHA256 checks a raw tag using a constant-time MAC comparison.
func VerifyHMACSHA256(data, key, tag []byte) bool { return digest.VerifyHMACSHA256(data, key, tag) }

// HMACSHA256 computes a hexadecimal authentication tag for the current data.
func (p *CryptoData) HMACSHA256(key []byte) *CryptoData {
	if p.err != nil {
		return p
	}
	p.data = HMACSHA256(p.data, key)
	return p.Hex()
}
