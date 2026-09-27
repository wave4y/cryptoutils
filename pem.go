package cryptoutils

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
)

const (
	MaxKeyDERSize = 64 << 10
	MaxKeyPEMSize = 128 << 10
)

func checkedPrivateKey(key crypto.PrivateKey) (crypto.PrivateKey, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return checkedRSAPrivate(k)
	case *ecdsa.PrivateKey:
		return checkedECDSAPrivate(k)
	case ed25519.PrivateKey:
		return checkedEd25519Private(k)
	case *ecdh.PrivateKey:
		return checkedECDHPrivate(k)
	default:
		return nil, fmt.Errorf("%w: unsupported private key type %T", ErrInvalidAsymmetricKey, key)
	}
}

func checkedPublicKey(key crypto.PublicKey) (crypto.PublicKey, error) {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return checkedRSAPublic(k)
	case *ecdsa.PublicKey:
		return checkedECDSAPublic(k)
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return nil, ErrInvalidAsymmetricKey
		}
		return append(ed25519.PublicKey(nil), k...), nil
	case *ecdh.PublicKey:
		return checkedECDHPublic(k)
	default:
		return nil, fmt.Errorf("%w: unsupported public key type %T", ErrInvalidAsymmetricKey, key)
	}
}

// MarshalPrivateKeyDER validates a supported key and exports unencrypted PKCS#8.
func MarshalPrivateKeyDER(key crypto.PrivateKey) ([]byte, error) {
	validated, err := checkedPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return x509.MarshalPKCS8PrivateKey(validated)
}

// MarshalPublicKeyDER exports SubjectPublicKeyInfo (PKIX) DER.
func MarshalPublicKeyDER(key crypto.PublicKey) ([]byte, error) {
	validated, err := checkedPublicKey(key)
	if err != nil {
		return nil, err
	}
	return x509.MarshalPKIXPublicKey(validated)
}

// ParsePrivateKeyDER accepts PKCS#8, RSA PKCS#1 and EC SEC1 keys, up to 64 KiB.
// NIST-curve ECDH keys use the same encoding as ECDSA and parse as ECDSA keys;
// call ParseECDHPrivateKeyDER to convert them to crypto/ecdh explicitly.
func ParsePrivateKeyDER(der []byte) (crypto.PrivateKey, error) {
	if err := preflightPrivateDER(der); err != nil {
		return nil, err
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return checkedPrivateKey(key)
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return checkedPrivateKey(key)
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return checkedPrivateKey(key)
	}
	return nil, fmt.Errorf("%w: invalid private key DER", ErrInvalidAsymmetricKey)
}

// ParsePublicKeyDER accepts PKIX or RSA PKCS#1 public keys, up to 64 KiB.
func ParsePublicKeyDER(der []byte) (crypto.PublicKey, error) {
	if err := singleDERSequence(der); err != nil {
		return nil, err
	}
	if key, err := x509.ParsePKIXPublicKey(der); err == nil {
		return checkedPublicKey(key)
	}
	if key, err := x509.ParsePKCS1PublicKey(der); err == nil {
		return checkedPublicKey(key)
	}
	return nil, fmt.Errorf("%w: invalid public key DER", ErrInvalidAsymmetricKey)
}

func singleDERSequence(der []byte) error {
	if len(der) == 0 || len(der) > MaxKeyDERSize {
		return ErrInvalidAsymmetricKey
	}
	var value asn1.RawValue
	rest, err := asn1.Unmarshal(der, &value)
	if err != nil || len(rest) != 0 || value.Class != 0 || value.Tag != asn1.TagSequence || !value.IsCompound {
		return ErrInvalidAsymmetricKey
	}
	return nil
}

// Bound RSA integers before x509's parser performs private-key validation and
// CRT precomputation. The DER size cap alone would allow very large moduli.
func preflightPrivateDER(der []byte) error {
	if err := singleDERSequence(der); err != nil {
		return err
	}
	var envelope struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
	}
	if _, err := asn1.Unmarshal(der, &envelope); err == nil {
		if envelope.Version != 0 {
			return ErrInvalidAsymmetricKey
		}
		if envelope.Algorithm.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}) {
			der = envelope.PrivateKey
			if err := singleDERSequence(der); err != nil {
				return err
			}
		}
	}
	var rsaDER struct {
		Version               int
		N                     *big.Int
		E                     int
		D, P, Q, DP, DQ, Qinv *big.Int
		Additional            []asn1.RawValue `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(der, &rsaDER); err == nil {
		if rsaDER.Version != 0 || len(rsaDER.Additional) != 0 {
			return ErrInvalidAsymmetricKey
		}
		if _, err := checkedRSAPublic(&rsa.PublicKey{N: rsaDER.N, E: rsaDER.E}); err != nil {
			return err
		}
		for _, n := range []*big.Int{rsaDER.D, rsaDER.P, rsaDER.Q, rsaDER.DP, rsaDER.DQ, rsaDER.Qinv} {
			if n == nil || n.Sign() < 0 || n.BitLen() > 8192 {
				return ErrInvalidAsymmetricKey
			}
		}
		if rsaDER.P.Cmp(big.NewInt(2)) <= 0 || rsaDER.Q.Cmp(big.NewInt(2)) <= 0 || new(big.Int).GCD(nil, nil, rsaDER.P, rsaDER.Q).Cmp(big.NewInt(1)) != 0 {
			return ErrInvalidAsymmetricKey
		}
	}
	return nil
}

func MarshalPrivateKeyPEM(key crypto.PrivateKey) ([]byte, error) {
	der, err := MarshalPrivateKeyDER(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func MarshalPublicKeyPEM(key crypto.PublicKey) ([]byte, error) {
	der, err := MarshalPublicKeyDER(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

func decodeSingleKeyPEM(encoded []byte) (*pem.Block, error) {
	if len(encoded) == 0 || len(encoded) > MaxKeyPEMSize {
		return nil, ErrInvalidAsymmetricKey
	}
	trimmed := bytes.TrimSpace(encoded)
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) || bytes.Count(trimmed, []byte("-----BEGIN ")) != 1 {
		return nil, ErrInvalidAsymmetricKey
	}
	block, rest := pem.Decode(trimmed)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 || len(block.Headers) != 0 || len(block.Bytes) > MaxKeyDERSize {
		return nil, ErrInvalidAsymmetricKey
	}
	return block, nil
}

// ParsePrivateKeyPEM requires exactly one unencrypted private-key block.
func ParsePrivateKeyPEM(encoded []byte) (crypto.PrivateKey, error) {
	block, err := decodeSingleKeyPEM(encoded)
	if err != nil {
		return nil, err
	}
	if err := preflightPrivateDER(block.Bytes); err != nil {
		return nil, err
	}
	var key crypto.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("%w: unsupported or encrypted PEM block", ErrInvalidAsymmetricKey)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidAsymmetricKey, err)
	}
	return checkedPrivateKey(key)
}

func ParsePublicKeyPEM(encoded []byte) (crypto.PublicKey, error) {
	block, err := decodeSingleKeyPEM(encoded)
	if err != nil {
		return nil, err
	}
	if err := singleDERSequence(block.Bytes); err != nil {
		return nil, err
	}
	var key crypto.PublicKey
	switch block.Type {
	case "PUBLIC KEY":
		key, err = x509.ParsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		key, err = x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, fmt.Errorf("%w: unsupported public PEM block", ErrInvalidAsymmetricKey)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidAsymmetricKey, err)
	}
	return checkedPublicKey(key)
}

func asECDHPrivate(key crypto.PrivateKey) (*ecdh.PrivateKey, error) {
	switch k := key.(type) {
	case *ecdh.PrivateKey:
		return k, nil
	case *ecdsa.PrivateKey:
		return k.ECDH()
	default:
		return nil, fmt.Errorf("%w: expected ECDH key", ErrInvalidAsymmetricKey)
	}
}

func asECDHPublic(key crypto.PublicKey) (*ecdh.PublicKey, error) {
	switch k := key.(type) {
	case *ecdh.PublicKey:
		return k, nil
	case *ecdsa.PublicKey:
		return k.ECDH()
	default:
		return nil, fmt.Errorf("%w: expected ECDH key", ErrInvalidAsymmetricKey)
	}
}

func ParseECDHPrivateKeyDER(der []byte) (*ecdh.PrivateKey, error) {
	key, err := ParsePrivateKeyDER(der)
	if err != nil {
		return nil, err
	}
	return asECDHPrivate(key)
}
func ParseECDHPublicKeyDER(der []byte) (*ecdh.PublicKey, error) {
	key, err := ParsePublicKeyDER(der)
	if err != nil {
		return nil, err
	}
	return asECDHPublic(key)
}
func ParseECDHPrivateKeyPEM(encoded []byte) (*ecdh.PrivateKey, error) {
	key, err := ParsePrivateKeyPEM(encoded)
	if err != nil {
		return nil, err
	}
	return asECDHPrivate(key)
}
func ParseECDHPublicKeyPEM(encoded []byte) (*ecdh.PublicKey, error) {
	key, err := ParsePublicKeyPEM(encoded)
	if err != nil {
		return nil, err
	}
	return asECDHPublic(key)
}
