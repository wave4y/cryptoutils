package derivation

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrPasswordMismatch    = errors.New("cryptoutils: password mismatch")
	ErrInvalidPasswordHash = errors.New("cryptoutils: invalid password hash")
)

const (
	DefaultBcryptCost = 12
	// MaxBcryptCost also applies to untrusted stored hashes during verification.
	MaxBcryptCost = 14
)

// HashBcrypt returns a self-contained bcrypt password hash with a random salt.
// Cost 0 selects DefaultBcryptCost; other accepted costs are 4..MaxBcryptCost.
// Passwords over 72 bytes are rejected, never silently truncated.
func HashBcrypt(password []byte, cost int) (string, error) {
	if len(password) > 72 {
		return "", fmt.Errorf("cryptoutils: bcrypt password exceeds 72 bytes")
	}
	if cost == 0 {
		cost = DefaultBcryptCost
	}
	if cost < bcrypt.MinCost || cost > MaxBcryptCost {
		return "", fmt.Errorf("cryptoutils: bcrypt cost must be 4..%d, or 0 for default", MaxBcryptCost)
	}
	encoded, err := bcrypt.GenerateFromPassword(password, cost)
	if err != nil {
		return "", fmt.Errorf("cryptoutils: bcrypt hash: %w", err)
	}
	return string(encoded), nil
}

// VerifyBcrypt validates the hash format and cost before performing expensive
// work. Versions 2a, 2b and 2y are accepted. A mismatch is ErrPasswordMismatch.
func VerifyBcrypt(password []byte, encoded string) error {
	if len(password) > 72 {
		return fmt.Errorf("cryptoutils: bcrypt password exceeds 72 bytes")
	}
	if len(encoded) != 60 || (encoded[:4] != "$2a$" && encoded[:4] != "$2b$" && encoded[:4] != "$2y$") || encoded[6] != '$' {
		return ErrInvalidPasswordHash
	}
	if encoded[4] < '0' || encoded[4] > '9' || encoded[5] < '0' || encoded[5] > '9' {
		return ErrInvalidPasswordHash
	}
	for _, c := range encoded[7:] {
		if !strings.ContainsRune("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", c) {
			return ErrInvalidPasswordHash
		}
	}
	cost, err := bcrypt.Cost([]byte(encoded))
	if err != nil || cost < bcrypt.MinCost || cost > MaxBcryptCost {
		return fmt.Errorf("%w: bcrypt cost must be 4..%d", ErrInvalidPasswordHash, MaxBcryptCost)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(encoded), password); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return ErrPasswordMismatch
		}
		return fmt.Errorf("%w: %v", ErrInvalidPasswordHash, err)
	}
	return nil
}

// HashArgon2id returns a PHC string containing the version, parameters, a random
// 16-byte salt and the hash. A nil options pointer selects the KDF defaults.
// For password storage, KeyLength is restricted to 16..64 bytes.
func HashArgon2id(password []byte, options *Argon2idOptions) (string, error) {
	o := DefaultArgon2idOptions()
	if options != nil {
		o = *options
	}
	if err := checkKDFInput(password); err != nil {
		return "", err
	}
	if err := validateArgon2idOptions(o); err != nil {
		return "", err
	}
	if o.KeyLength < 16 || o.KeyLength > 64 {
		return "", fmt.Errorf("%w: password hash must contain 16..64 bytes", ErrKDFParameters)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("cryptoutils: password salt: %w", err)
	}
	key, err := Argon2id(password, salt, &o)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", o.Memory, o.Time, o.Threads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyArgon2id checks a canonical Argon2id v19 PHC string. The same bounded
// resource policy as Argon2id applies before any memory-hard computation.
func VerifyArgon2id(password []byte, encoded string) error {
	if err := checkKDFInput(password); err != nil {
		return err
	}
	if len(encoded) > 512 {
		return ErrInvalidPasswordHash
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return ErrInvalidPasswordHash
	}
	parameters := strings.Split(parts[3], ",")
	if len(parameters) != 3 {
		return ErrInvalidPasswordHash
	}
	values := [3]int{}
	for i, prefix := range []string{"m=", "t=", "p="} {
		if !strings.HasPrefix(parameters[i], prefix) {
			return ErrInvalidPasswordHash
		}
		decimal := strings.TrimPrefix(parameters[i], prefix)
		value, err := strconv.Atoi(decimal)
		if err != nil || value < 1 || strconv.Itoa(value) != decimal {
			return ErrInvalidPasswordHash
		}
		values[i] = value
	}
	decode := base64.RawStdEncoding.Strict()
	salt, err := decode.DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > 64 || decode.EncodeToString(salt) != parts[4] {
		return ErrInvalidPasswordHash
	}
	want, err := decode.DecodeString(parts[5])
	if err != nil || len(want) < 16 || len(want) > 64 || decode.EncodeToString(want) != parts[5] {
		return ErrInvalidPasswordHash
	}
	o := Argon2idOptions{Memory: values[0], Time: values[1], Threads: values[2], KeyLength: len(want)}
	if err := validateArgon2idOptions(o); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPasswordHash, err)
	}
	got, err := Argon2id(password, salt, &o)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrPasswordMismatch
	}
	return nil
}
