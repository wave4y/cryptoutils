package pqc

import (
	"bytes"
	"io"

	"github.com/wave4y/cryptoutils/pqc/internal/reference/sign"
	"github.com/wave4y/cryptoutils/pqc/internal/reference/sign/mldsa/mldsa44"
	"github.com/wave4y/cryptoutils/pqc/internal/reference/sign/mldsa/mldsa65"
	"github.com/wave4y/cryptoutils/pqc/internal/reference/sign/mldsa/mldsa87"
	"github.com/wave4y/cryptoutils/pqc/internal/reference/sign/slhdsa"
)

// SignatureParameter selects a complete FIPS 204 or FIPS 205 parameter set.
// MaxMessageSize bounds work and allocation for pure signature operations.
const MaxMessageSize = 16 << 20

type SignatureParameter string

const (
	MLDSA44         SignatureParameter = "ML-DSA-44"
	MLDSA65         SignatureParameter = "ML-DSA-65"
	MLDSA87         SignatureParameter = "ML-DSA-87"
	SLHDSASHA2128s  SignatureParameter = "SLH-DSA-SHA2-128s"
	SLHDSASHA2128f  SignatureParameter = "SLH-DSA-SHA2-128f"
	SLHDSASHA2192s  SignatureParameter = "SLH-DSA-SHA2-192s"
	SLHDSASHA2192f  SignatureParameter = "SLH-DSA-SHA2-192f"
	SLHDSASHA2256s  SignatureParameter = "SLH-DSA-SHA2-256s"
	SLHDSASHA2256f  SignatureParameter = "SLH-DSA-SHA2-256f"
	SLHDSASHAKE128s SignatureParameter = "SLH-DSA-SHAKE-128s"
	SLHDSASHAKE128f SignatureParameter = "SLH-DSA-SHAKE-128f"
	SLHDSASHAKE192s SignatureParameter = "SLH-DSA-SHAKE-192s"
	SLHDSASHAKE192f SignatureParameter = "SLH-DSA-SHAKE-192f"
	SLHDSASHAKE256s SignatureParameter = "SLH-DSA-SHAKE-256s"
	SLHDSASHAKE256f SignatureParameter = "SLH-DSA-SHAKE-256f"
)

func signatureScheme(parameter SignatureParameter) (sign.Scheme, error) {
	switch parameter {
	case MLDSA44:
		return mldsa44.Scheme(), nil
	case MLDSA65:
		return mldsa65.Scheme(), nil
	case MLDSA87:
		return mldsa87.Scheme(), nil
	}
	id, err := slhdsa.IDByName(string(parameter))
	if err != nil {
		return nil, ErrParameter
	}
	return id.Scheme(), nil
}

func signatureSeedSize(parameter SignatureParameter, scheme sign.Scheme) int {
	if parameter == MLDSA44 || parameter == MLDSA65 || parameter == MLDSA87 {
		return 32
	}
	return scheme.PublicKeySize() / 2 * 3
}

// GenerateSignatureKey returns standard FIPS public and private key encodings.
// A nil random reader selects crypto/rand.
func GenerateSignatureKey(parameter SignatureParameter, random io.Reader) (publicKey, privateKey []byte, err error) {
	scheme, err := signatureScheme(parameter)
	if err != nil {
		return nil, nil, err
	}
	seed, err := entropy(random, signatureSeedSize(parameter, scheme))
	if err != nil {
		return nil, nil, err
	}
	return DeriveSignatureKey(parameter, seed)
}

// DeriveSignatureKey derives keys from a secret random seed: 32 bytes for ML-DSA;
// SK.seed || SK.prf || PK.seed (3*n bytes) for SLH-DSA, as specified by FIPS 205.
func DeriveSignatureKey(parameter SignatureParameter, seed []byte) (publicKey, privateKey []byte, err error) {
	scheme, err := signatureScheme(parameter)
	if err != nil {
		return nil, nil, err
	}
	if len(seed) != signatureSeedSize(parameter, scheme) {
		return nil, nil, ErrSeed
	}
	if parameter == MLDSA44 || parameter == MLDSA65 || parameter == MLDSA87 {
		pk, sk := scheme.DeriveKey(seed)
		publicKey, _ = pk.MarshalBinary()
		privateKey, _ = sk.MarshalBinary()
		return
	}
	id, _ := slhdsa.IDByName(string(parameter))
	pk, sk, err := slhdsa.GenerateKey(bytes.NewReader(seed), id)
	if err != nil {
		return nil, nil, err
	}
	publicKey, err = pk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	privateKey, err = sk.MarshalBinary()
	return
}

// Sign signs an un-hashed message using the standard pure interface and fresh
// signing randomness. Context is domain separation data of at most 255 bytes.
func Sign(parameter SignatureParameter, privateKey, message, context []byte, random io.Reader) ([]byte, error) {
	return signMessage(parameter, privateKey, message, context, random, false)
}

// SignDeterministic uses the optional deterministic FIPS signing mode. For
// applications with a reliable random source prefer Sign.
func SignDeterministic(parameter SignatureParameter, privateKey, message, context []byte) ([]byte, error) {
	return signMessage(parameter, privateKey, message, context, nil, true)
}

func signMessage(parameter SignatureParameter, privateKey, message, context []byte, random io.Reader, deterministic bool) ([]byte, error) {
	if len(message) > MaxMessageSize {
		return nil, ErrMessageTooLarge
	}
	if len(context) > 255 {
		return nil, ErrContext
	}
	scheme, err := signatureScheme(parameter)
	if err != nil {
		return nil, err
	}
	if len(privateKey) != scheme.PrivateKeySize() {
		return nil, ErrKey
	}
	var rnd [32]byte
	if parameter == MLDSA44 || parameter == MLDSA65 || parameter == MLDSA87 {
		if !deterministic {
			r, err := entropy(random, len(rnd))
			if err != nil {
				return nil, err
			}
			copy(rnd[:], r)
		}
		signature := make([]byte, scheme.SignatureSize())
		switch parameter {
		case MLDSA44:
			var sk mldsa44.PrivateKey
			if err := sk.UnmarshalBinary(privateKey); err != nil {
				return nil, ErrKey
			}
			err = mldsa44.SignToWithRandomness(&sk, message, context, rnd, signature)
		case MLDSA65:
			var sk mldsa65.PrivateKey
			if err := sk.UnmarshalBinary(privateKey); err != nil {
				return nil, ErrKey
			}
			err = mldsa65.SignToWithRandomness(&sk, message, context, rnd, signature)
		case MLDSA87:
			var sk mldsa87.PrivateKey
			if err := sk.UnmarshalBinary(privateKey); err != nil {
				return nil, ErrKey
			}
			err = mldsa87.SignToWithRandomness(&sk, message, context, rnd, signature)
		}
		if err != nil {
			return nil, err
		}
		return signature, nil
	}
	id, _ := slhdsa.IDByName(string(parameter))
	sk := slhdsa.PrivateKey{ID: id}
	if err := sk.UnmarshalBinary(privateKey); err != nil {
		return nil, ErrKey
	}
	var signature []byte
	if deterministic {
		signature, err = slhdsa.SignDeterministic(&sk, slhdsa.NewMessage(message), context)
	} else {
		signature, err = slhdsa.SignRandomized(&sk, random, slhdsa.NewMessage(message), context)
	}
	if err != nil {
		return nil, err
	}
	// An expanded SLH key includes its public root. Refuse an inconsistent
	// imported key rather than returning an unverifiable signature.
	publicKey := sk.PublicKey()
	if !slhdsa.Verify(&publicKey, slhdsa.NewMessage(message), signature, context) {
		return nil, ErrKey
	}
	return signature, nil
}

// Verify checks a pure FIPS signature. It returns nil only for a valid signature.
func Verify(parameter SignatureParameter, publicKey, message, signature, context []byte) error {
	if len(message) > MaxMessageSize {
		return ErrMessageTooLarge
	}
	if len(context) > 255 {
		return ErrContext
	}
	scheme, err := signatureScheme(parameter)
	if err != nil {
		return err
	}
	if len(publicKey) != scheme.PublicKeySize() {
		return ErrKey
	}
	if len(signature) != scheme.SignatureSize() {
		return ErrVerification
	}
	pk, err := scheme.UnmarshalBinaryPublicKey(publicKey)
	if err != nil {
		return ErrKey
	}
	if !scheme.Verify(pk, message, signature, &sign.SignatureOpts{Context: string(context)}) {
		return ErrVerification
	}
	return nil
}
