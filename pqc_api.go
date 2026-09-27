package cryptoutils

import (
	"errors"
	"github.com/wave4y/cryptoutils/pqc"
)

type MLKEMParameter = pqc.KEMParameter
type PQSignatureParameter = pqc.SignatureParameter
type MLKEMPublicKey = pqc.MLKEMPublicKey
type MLKEMPrivateKey = pqc.MLKEMPrivateKey

const (
	MLKEM512        = pqc.MLKEM512
	MLKEM768        = pqc.MLKEM768
	MLKEM1024       = pqc.MLKEM1024
	MLDSA44         = pqc.MLDSA44
	MLDSA65         = pqc.MLDSA65
	MLDSA87         = pqc.MLDSA87
	SLHDSASHA2128s  = pqc.SLHDSASHA2128s
	SLHDSASHA2128f  = pqc.SLHDSASHA2128f
	SLHDSASHA2192s  = pqc.SLHDSASHA2192s
	SLHDSASHA2192f  = pqc.SLHDSASHA2192f
	SLHDSASHA2256s  = pqc.SLHDSASHA2256s
	SLHDSASHA2256f  = pqc.SLHDSASHA2256f
	SLHDSASHAKE128s = pqc.SLHDSASHAKE128s
	SLHDSASHAKE128f = pqc.SLHDSASHAKE128f
	SLHDSASHAKE192s = pqc.SLHDSASHAKE192s
	SLHDSASHAKE192f = pqc.SLHDSASHAKE192f
	SLHDSASHAKE256s = pqc.SLHDSASHAKE256s
	SLHDSASHAKE256f = pqc.SLHDSASHAKE256f
)

// GenerateMLKEMKey returns an encapsulation key and a decapsulation key.
func GenerateMLKEMKey(parameter MLKEMParameter) (*MLKEMPublicKey, *MLKEMPrivateKey, error) {
	return pqc.GenerateMLKEM(parameter, nil)
}
func ParseMLKEMPublicKey(parameter MLKEMParameter, encoded []byte) (*MLKEMPublicKey, error) {
	return pqc.ParseMLKEMPublicKey(parameter, encoded)
}
func ParseMLKEMPrivateKey(parameter MLKEMParameter, encoded []byte) (*MLKEMPrivateKey, error) {
	return pqc.ParseMLKEMPrivateKey(parameter, encoded)
}

// EncapsulateMLKEM returns ciphertext then a 32-byte shared secret. KEM establishes
// key material; it does not itself encrypt application data or authenticate peers.
func EncapsulateMLKEM(key *MLKEMPublicKey) (ciphertext, sharedSecret []byte, err error) {
	return pqc.EncapsulateMLKEM(key, nil)
}

// DecapsulateMLKEM applies FIPS 203 implicit rejection for corrupted, correctly
// sized ciphertext. Use a derived key in an authenticated protocol to detect it.
func DecapsulateMLKEM(ciphertext []byte, key *MLKEMPrivateKey) ([]byte, error) {
	return pqc.DecapsulateMLKEM(key, ciphertext)
}

// GeneratePQSignatureKey returns raw public/private keys for the exact parameter
// set. Store the parameter identifier alongside serialized keys and signatures.
func GeneratePQSignatureKey(parameter PQSignatureParameter) (publicKey, privateKey []byte, err error) {
	return pqc.GenerateSignatureKey(parameter, nil)
}

// SignPQ uses randomized pure ML-DSA or SLH-DSA with a context of at most 255 bytes.
func SignPQ(parameter PQSignatureParameter, data, privateKey, context []byte) ([]byte, error) {
	return pqc.Sign(parameter, privateKey, data, context, nil)
}
func VerifyPQ(parameter PQSignatureParameter, data, publicKey, signature, context []byte) error {
	return pqc.Verify(parameter, publicKey, data, signature, context)
}
func isMLDSA(parameter PQSignatureParameter) bool {
	return parameter == MLDSA44 || parameter == MLDSA65 || parameter == MLDSA87
}
func isSLHDSA(parameter PQSignatureParameter) bool {
	switch parameter {
	case SLHDSASHA2128s, SLHDSASHA2128f, SLHDSASHA2192s, SLHDSASHA2192f, SLHDSASHA2256s, SLHDSASHA2256f, SLHDSASHAKE128s, SLHDSASHAKE128f, SLHDSASHAKE192s, SLHDSASHAKE192f, SLHDSASHAKE256s, SLHDSASHAKE256f:
		return true
	}
	return false
}
func GenerateMLDSAKey(parameter PQSignatureParameter) ([]byte, []byte, error) {
	if !isMLDSA(parameter) {
		return nil, nil, errors.New("cryptoutils: expected an ML-DSA parameter set")
	}
	return GeneratePQSignatureKey(parameter)
}
func GenerateSLHDSAKey(parameter PQSignatureParameter) ([]byte, []byte, error) {
	if !isSLHDSA(parameter) {
		return nil, nil, errors.New("cryptoutils: expected an SLH-DSA parameter set")
	}
	return GeneratePQSignatureKey(parameter)
}
func SignMLDSA(parameter PQSignatureParameter, data, privateKey, context []byte) ([]byte, error) {
	if !isMLDSA(parameter) {
		return nil, errors.New("cryptoutils: expected an ML-DSA parameter set")
	}
	return SignPQ(parameter, data, privateKey, context)
}
func VerifyMLDSA(parameter PQSignatureParameter, data, publicKey, signature, context []byte) error {
	if !isMLDSA(parameter) {
		return errors.New("cryptoutils: expected an ML-DSA parameter set")
	}
	return VerifyPQ(parameter, data, publicKey, signature, context)
}
func SignSLHDSA(parameter PQSignatureParameter, data, privateKey, context []byte) ([]byte, error) {
	if !isSLHDSA(parameter) {
		return nil, errors.New("cryptoutils: expected an SLH-DSA parameter set")
	}
	return SignPQ(parameter, data, privateKey, context)
}
func VerifySLHDSA(parameter PQSignatureParameter, data, publicKey, signature, context []byte) error {
	if !isSLHDSA(parameter) {
		return errors.New("cryptoutils: expected an SLH-DSA parameter set")
	}
	return VerifyPQ(parameter, data, publicKey, signature, context)
}
func (p *CryptoData) PQSign(parameter PQSignatureParameter, key, context []byte) *CryptoData {
	if p.err != nil {
		return p
	}
	out, err := SignPQ(parameter, p.data, key, context)
	if err != nil {
		return p.fail(err)
	}
	p.data = out
	return p
}
func (p *CryptoData) PQVerify(parameter PQSignatureParameter, key, signature, context []byte) *CryptoData {
	if p.err != nil {
		return p
	}
	return p.fail(VerifyPQ(parameter, p.data, key, signature, context))
}
func (p *CryptoData) MLDSASign(parameter PQSignatureParameter, key, context []byte) *CryptoData {
	if p.err != nil {
		return p
	}
	if !isMLDSA(parameter) {
		return p.fail(errors.New("cryptoutils: expected an ML-DSA parameter set"))
	}
	return p.PQSign(parameter, key, context)
}
func (p *CryptoData) MLDSAVerify(parameter PQSignatureParameter, key, signature, context []byte) *CryptoData {
	if p.err != nil {
		return p
	}
	if !isMLDSA(parameter) {
		return p.fail(errors.New("cryptoutils: expected an ML-DSA parameter set"))
	}
	return p.PQVerify(parameter, key, signature, context)
}
func (p *CryptoData) SLHDSASign(parameter PQSignatureParameter, key, context []byte) *CryptoData {
	if p.err != nil {
		return p
	}
	if !isSLHDSA(parameter) {
		return p.fail(errors.New("cryptoutils: expected an SLH-DSA parameter set"))
	}
	return p.PQSign(parameter, key, context)
}
func (p *CryptoData) SLHDSAVerify(parameter PQSignatureParameter, key, signature, context []byte) *CryptoData {
	if p.err != nil {
		return p
	}
	if !isSLHDSA(parameter) {
		return p.fail(errors.New("cryptoutils: expected an SLH-DSA parameter set"))
	}
	return p.PQVerify(parameter, key, signature, context)
}
