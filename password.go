package cryptoutils

import (
	"github.com/wave4y/cryptoutils/internal/derivation"
)

var (
	ErrPasswordMismatch    = derivation.ErrPasswordMismatch
	ErrInvalidPasswordHash = derivation.ErrInvalidPasswordHash
)

const (
	DefaultBcryptCost = derivation.DefaultBcryptCost
	// MaxBcryptCost also applies to untrusted stored hashes during verification.
	MaxBcryptCost = derivation.MaxBcryptCost
)

// HashBcrypt returns a self-contained bcrypt password hash with a random salt.
// Cost 0 selects DefaultBcryptCost; other accepted costs are 4..MaxBcryptCost.
// Passwords over 72 bytes are rejected, never silently truncated.
func HashBcrypt(password []byte, cost int) (string, error) {
	return derivation.HashBcrypt(password, cost)
}

// VerifyBcrypt validates the hash format and cost before performing expensive
// work. Versions 2a, 2b and 2y are accepted. A mismatch is ErrPasswordMismatch.
func VerifyBcrypt(password []byte, encoded string) error {
	return derivation.VerifyBcrypt(password, encoded)
}

// HashArgon2id returns a PHC string containing the version, parameters, a random
// 16-byte salt and the hash. A nil options pointer selects the KDF defaults.
// For password storage, KeyLength is restricted to 16..64 bytes.
func HashArgon2id(password []byte, options *Argon2idOptions) (string, error) {
	return derivation.HashArgon2id(password, (*derivation.Argon2idOptions)(options))
}

// VerifyArgon2id checks a canonical Argon2id v19 PHC string. The same bounded
// resource policy as Argon2id applies before any memory-hard computation.
func VerifyArgon2id(password []byte, encoded string) error {
	return derivation.VerifyArgon2id(password, encoded)
}

// HashBcrypt replaces the current data with a self-contained bcrypt hash.
func (p *CryptoData) HashBcrypt(cost int) *CryptoData {
	if p.err != nil {
		return p
	}
	encoded, err := HashBcrypt(p.data, cost)
	if err != nil {
		return p.fail(err)
	}
	p.data = []byte(encoded)
	return p
}

// HashArgon2id replaces the current data with a self-contained PHC hash.
func (p *CryptoData) HashArgon2id(options *Argon2idOptions) *CryptoData {
	if p.err != nil {
		return p
	}
	encoded, err := HashArgon2id(p.data, options)
	if err != nil {
		return p.fail(err)
	}
	p.data = []byte(encoded)
	return p
}

// VerifyBcrypt preserves the current password on success; failure is sticky.
func (p *CryptoData) VerifyBcrypt(encoded string) *CryptoData {
	if p.err != nil {
		return p
	}
	return p.fail(VerifyBcrypt(p.data, encoded))
}

// VerifyArgon2id preserves the current password on success; failure is sticky.
func (p *CryptoData) VerifyArgon2id(encoded string) *CryptoData {
	if p.err != nil {
		return p
	}
	return p.fail(VerifyArgon2id(p.data, encoded))
}
