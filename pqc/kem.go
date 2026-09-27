// Package pqc provides FIPS 203 ML-KEM and FIPS 204/205 digital signatures.
// The algorithm cores are locally adapted from CIRCL; see internal/reference/README.md.
package pqc

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/wave4y/cryptoutils/pqc/internal/reference/kem"
	"github.com/wave4y/cryptoutils/pqc/internal/reference/kem/mlkem/mlkem1024"
	"github.com/wave4y/cryptoutils/pqc/internal/reference/kem/mlkem/mlkem512"
	"github.com/wave4y/cryptoutils/pqc/internal/reference/kem/mlkem/mlkem768"
)

var (
	ErrMessageTooLarge = errors.New("pqc: message exceeds 16 MiB")
	ErrParameter       = errors.New("pqc: unsupported parameter set")
	ErrKey             = errors.New("pqc: invalid key")
	ErrSeed            = errors.New("pqc: invalid seed length")
	ErrContext         = errors.New("pqc: context exceeds 255 bytes")
	ErrVerification    = errors.New("pqc: signature verification failed")
)

type KEMParameter string

const (
	MLKEM512  KEMParameter = "ML-KEM-512"
	MLKEM768  KEMParameter = "ML-KEM-768"
	MLKEM1024 KEMParameter = "ML-KEM-1024"
)

// MLKEMPublicKey is a validated encapsulation key. Its zero value is invalid.
type MLKEMPublicKey struct {
	parameter KEMParameter
	key       kem.PublicKey
}

// MLKEMPrivateKey is a validated decapsulation key. Its zero value is invalid.
type MLKEMPrivateKey struct {
	parameter KEMParameter
	key       kem.PrivateKey
}

func (k *MLKEMPublicKey) Bytes() []byte {
	if k == nil || k.key == nil {
		return nil
	}
	b, _ := k.key.MarshalBinary()
	return b
}
func (k *MLKEMPrivateKey) Bytes() []byte {
	if k == nil || k.key == nil {
		return nil
	}
	b, _ := k.key.MarshalBinary()
	return b
}
func (k *MLKEMPublicKey) Parameter() KEMParameter {
	if k == nil {
		return ""
	}
	return k.parameter
}
func (k *MLKEMPrivateKey) Parameter() KEMParameter {
	if k == nil {
		return ""
	}
	return k.parameter
}

func kemScheme(parameter KEMParameter) (kem.Scheme, error) {
	switch parameter {
	case MLKEM512:
		return mlkem512.Scheme(), nil
	case MLKEM768:
		return mlkem768.Scheme(), nil
	case MLKEM1024:
		return mlkem1024.Scheme(), nil
	}
	return nil, ErrParameter
}

func entropy(random io.Reader, size int) ([]byte, error) {
	if random == nil {
		random = rand.Reader
	}
	seed := make([]byte, size)
	if _, err := io.ReadFull(random, seed); err != nil {
		return nil, fmt.Errorf("pqc: random source: %w", err)
	}
	return seed, nil
}

// GenerateMLKEM creates a key pair. A nil random reader selects crypto/rand.
func GenerateMLKEM(parameter KEMParameter, random io.Reader) (*MLKEMPublicKey, *MLKEMPrivateKey, error) {
	scheme, err := kemScheme(parameter)
	if err != nil {
		return nil, nil, err
	}
	seed, err := entropy(random, scheme.SeedSize())
	if err != nil {
		return nil, nil, err
	}
	return DeriveMLKEM(parameter, seed)
}

// DeriveMLKEM deterministically creates a key pair from a 64-byte seed d || z.
// The seed must be independently and securely generated and kept secret.
func DeriveMLKEM(parameter KEMParameter, seed []byte) (*MLKEMPublicKey, *MLKEMPrivateKey, error) {
	scheme, err := kemScheme(parameter)
	if err != nil {
		return nil, nil, err
	}
	if len(seed) != scheme.SeedSize() {
		return nil, nil, ErrSeed
	}
	pk, sk := scheme.DeriveKeyPair(seed)
	return &MLKEMPublicKey{parameter, pk}, &MLKEMPrivateKey{parameter, sk}, nil
}

func ParseMLKEMPublicKey(parameter KEMParameter, encoded []byte) (*MLKEMPublicKey, error) {
	scheme, err := kemScheme(parameter)
	if err != nil {
		return nil, err
	}
	key, err := scheme.UnmarshalBinaryPublicKey(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKey, err)
	}
	return &MLKEMPublicKey{parameter, key}, nil
}
func ParseMLKEMPrivateKey(parameter KEMParameter, encoded []byte) (*MLKEMPrivateKey, error) {
	scheme, err := kemScheme(parameter)
	if err != nil {
		return nil, err
	}
	key, err := scheme.UnmarshalBinaryPrivateKey(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKey, err)
	}
	canonical, _ := key.MarshalBinary()
	if !bytes.Equal(canonical, encoded) {
		return nil, ErrKey
	}
	return &MLKEMPrivateKey{parameter, key}, nil
}

// EncapsulateMLKEM produces a ciphertext and an independently random shared key.
func EncapsulateMLKEM(publicKey *MLKEMPublicKey, random io.Reader) (ciphertext, sharedSecret []byte, err error) {
	if publicKey == nil || publicKey.key == nil {
		return nil, nil, ErrKey
	}
	scheme, err := kemScheme(publicKey.parameter)
	if err != nil {
		return nil, nil, err
	}
	seed, err := entropy(random, scheme.EncapsulationSeedSize())
	if err != nil {
		return nil, nil, err
	}
	return scheme.EncapsulateDeterministically(publicKey.key, seed)
}

// DecapsulateMLKEM recovers a shared key. FIPS 203 implicit rejection means a
// modified ciphertext of the correct size produces a different key, not an error.
// Use the shared key with an authenticated encryption protocol for confirmation.
func DecapsulateMLKEM(privateKey *MLKEMPrivateKey, ciphertext []byte) ([]byte, error) {
	if privateKey == nil || privateKey.key == nil {
		return nil, ErrKey
	}
	scheme, err := kemScheme(privateKey.parameter)
	if err != nil {
		return nil, err
	}
	return scheme.Decapsulate(privateKey.key, ciphertext)
}
