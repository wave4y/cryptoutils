package cryptoutils

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"

	"github.com/wave4y/cryptoutils/internal/asymmetric"
)

var (
	ErrInvalidAsymmetricKey  = asymmetric.ErrInvalidAsymmetricKey
	ErrSignatureVerification = asymmetric.ErrSignatureVerification
)

// MaxPublicKeyMessage bounds a single signing or verification input.
const MaxPublicKeyMessage = asymmetric.MaxPublicKeyMessage

const (
	MaxKeyDERSize = asymmetric.MaxKeyDERSize
	MaxKeyPEMSize = asymmetric.MaxKeyPEMSize
)

// ElGamalPublicKey and ElGamalPrivateKey retain the upstream legacy key format.
type ElGamalPublicKey = asymmetric.ElGamalPublicKey
type ElGamalPrivateKey = asymmetric.ElGamalPrivateKey

// GenerateRSAKey creates a two-prime RSA key of 2048..8192 bits.
func GenerateRSAKey(bits int) (*rsa.PrivateKey, error) {
	return asymmetric.GenerateRSAKey(bits)
}

// EncryptRSAOAEP encrypts a short message using SHA-256 for OAEP and MGF1.
// The label must match during decryption. Maximum input is modulusBytes - 66.
func EncryptRSAOAEP(plaintext []byte, key *rsa.PublicKey, label []byte) ([]byte, error) {
	return asymmetric.EncryptRSAOAEP(plaintext, key, label)
}

func DecryptRSAOAEP(ciphertext []byte, key *rsa.PrivateKey, label []byte) ([]byte, error) {
	return asymmetric.DecryptRSAOAEP(ciphertext, key, label)
}

// SignRSAPSS hashes a message with SHA-256 and signs using a 32-byte PSS salt.
func SignRSAPSS(message []byte, key *rsa.PrivateKey) ([]byte, error) {
	return asymmetric.SignRSAPSS(message, key)
}

func VerifyRSAPSS(message, signature []byte, key *rsa.PublicKey) error {
	return asymmetric.VerifyRSAPSS(message, signature, key)
}

func GenerateECDSAKey(curve string) (*ecdsa.PrivateKey, error) {
	return asymmetric.GenerateECDSAKey(curve)
}

// SignECDSA returns an ASN.1 DER (r,s) signature. P-256/P-384/P-521 use
// SHA-256/SHA-384/SHA-512 respectively; the input is a message, not a digest.
func SignECDSA(message []byte, key *ecdsa.PrivateKey) ([]byte, error) {
	return asymmetric.SignECDSA(message, key)
}

func VerifyECDSA(message, signature []byte, key *ecdsa.PublicKey) error {
	return asymmetric.VerifyECDSA(message, signature, key)
}

func GenerateEd25519Key() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return asymmetric.GenerateEd25519Key()
}

func SignEd25519(message []byte, key ed25519.PrivateKey) ([]byte, error) {
	return asymmetric.SignEd25519(message, key)
}

func VerifyEd25519(message, signature []byte, key ed25519.PublicKey) error {
	return asymmetric.VerifyEd25519(message, signature, key)
}

// GenerateECDHKey returns a private/public key pair for P256/P384/P521/X25519.
func GenerateECDHKey(curve string) (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	return asymmetric.GenerateECDHKey(curve)
}

// ECDH returns a raw shared secret. Derive application keys with HKDF and bind
// the authenticated protocol context; bare ECDH does not authenticate a peer.
func ECDH(privateKey *ecdh.PrivateKey, publicKey *ecdh.PublicKey) ([]byte, error) {
	return asymmetric.ECDH(privateKey, publicKey)
}

// GenerateElGamalKey creates a key in the fixed 2048-bit group.
// Deprecated: legacy/CTF only; this primitive is unauthenticated and not constant time.
func GenerateElGamalKey() (*ElGamalPrivateKey, error) {
	return asymmetric.GenerateElGamalKey()
}

// EncryptElGamal uses the upstream OpenPGP-style PKCS#1 v1.5 padding and returns
// fixed-width c1 || c2 (256 bytes each). This is not an OpenPGP packet.
// Deprecated: legacy/CTF only; this encryption does not authenticate ciphertext.
func EncryptElGamal(plaintext []byte, key *ElGamalPublicKey) ([]byte, error) {
	return asymmetric.EncryptElGamal(plaintext, key)
}

// DecryptElGamal accepts fixed-width c1 || c2. Do not expose its padding errors
// to untrusted clients: legacy ElGamal is vulnerable to chosen-ciphertext attacks.
// Deprecated: legacy/CTF only.
func DecryptElGamal(ciphertext []byte, key *ElGamalPrivateKey) ([]byte, error) {
	return asymmetric.DecryptElGamal(ciphertext, key)
}

// MarshalPrivateKeyDER validates a supported key and exports unencrypted PKCS#8.
func MarshalPrivateKeyDER(key crypto.PrivateKey) ([]byte, error) {
	return asymmetric.MarshalPrivateKeyDER(key)
}

// MarshalPublicKeyDER exports SubjectPublicKeyInfo (PKIX) DER.
func MarshalPublicKeyDER(key crypto.PublicKey) ([]byte, error) {
	return asymmetric.MarshalPublicKeyDER(key)
}

// ParsePrivateKeyDER accepts PKCS#8, RSA PKCS#1 and EC SEC1 keys, up to 64 KiB.
// NIST-curve ECDH keys use the same encoding as ECDSA and parse as ECDSA keys;
// call ParseECDHPrivateKeyDER to convert them to crypto/ecdh explicitly.
func ParsePrivateKeyDER(der []byte) (crypto.PrivateKey, error) {
	return asymmetric.ParsePrivateKeyDER(der)
}

// ParsePublicKeyDER accepts PKIX or RSA PKCS#1 public keys, up to 64 KiB.
func ParsePublicKeyDER(der []byte) (crypto.PublicKey, error) {
	return asymmetric.ParsePublicKeyDER(der)
}

func MarshalPrivateKeyPEM(key crypto.PrivateKey) ([]byte, error) {
	return asymmetric.MarshalPrivateKeyPEM(key)
}

func MarshalPublicKeyPEM(key crypto.PublicKey) ([]byte, error) {
	return asymmetric.MarshalPublicKeyPEM(key)
}

// ParsePrivateKeyPEM requires exactly one unencrypted private-key block.
func ParsePrivateKeyPEM(encoded []byte) (crypto.PrivateKey, error) {
	return asymmetric.ParsePrivateKeyPEM(encoded)
}

func ParsePublicKeyPEM(encoded []byte) (crypto.PublicKey, error) {
	return asymmetric.ParsePublicKeyPEM(encoded)
}

func ParseECDHPrivateKeyDER(der []byte) (*ecdh.PrivateKey, error) {
	return asymmetric.ParseECDHPrivateKeyDER(der)
}

func ParseECDHPublicKeyDER(der []byte) (*ecdh.PublicKey, error) {
	return asymmetric.ParseECDHPublicKeyDER(der)
}

func ParseECDHPrivateKeyPEM(encoded []byte) (*ecdh.PrivateKey, error) {
	return asymmetric.ParseECDHPrivateKeyPEM(encoded)
}

func ParseECDHPublicKeyPEM(encoded []byte) (*ecdh.PublicKey, error) {
	return asymmetric.ParseECDHPublicKeyPEM(encoded)
}

func (p *CryptoData) RSAOAEPEncrypt(key *rsa.PublicKey, label []byte) *CryptoData {
	if p.err != nil {
		return p
	}
	out, err := EncryptRSAOAEP(p.data, key, label)
	return p.setAsymmetricResult(out, err)
}
func (p *CryptoData) RSAOAEPDecrypt(key *rsa.PrivateKey, label []byte) *CryptoData {
	if p.err != nil {
		return p
	}
	out, err := DecryptRSAOAEP(p.data, key, label)
	return p.setAsymmetricResult(out, err)
}
func (p *CryptoData) RSAPSSSign(key *rsa.PrivateKey) *CryptoData {
	if p.err != nil {
		return p
	}
	out, err := SignRSAPSS(p.data, key)
	return p.setAsymmetricResult(out, err)
}
func (p *CryptoData) RSAPSSVerify(key *rsa.PublicKey, signature []byte) *CryptoData {
	if p.err != nil {
		return p
	}
	return p.fail(VerifyRSAPSS(p.data, signature, key))
}
func (p *CryptoData) ECDSASign(key *ecdsa.PrivateKey) *CryptoData {
	if p.err != nil {
		return p
	}
	out, err := SignECDSA(p.data, key)
	return p.setAsymmetricResult(out, err)
}
func (p *CryptoData) ECDSAVerify(key *ecdsa.PublicKey, signature []byte) *CryptoData {
	if p.err != nil {
		return p
	}
	return p.fail(VerifyECDSA(p.data, signature, key))
}
func (p *CryptoData) Ed25519Sign(key ed25519.PrivateKey) *CryptoData {
	if p.err != nil {
		return p
	}
	out, err := SignEd25519(p.data, key)
	return p.setAsymmetricResult(out, err)
}
func (p *CryptoData) Ed25519Verify(key ed25519.PublicKey, signature []byte) *CryptoData {
	if p.err != nil {
		return p
	}
	return p.fail(VerifyEd25519(p.data, signature, key))
}

// ECDH replaces the current data with a shared secret; the input data is unused.
func (p *CryptoData) ECDH(private *ecdh.PrivateKey, public *ecdh.PublicKey) *CryptoData {
	if p.err != nil {
		return p
	}
	out, err := ECDH(private, public)
	return p.setAsymmetricResult(out, err)
}
func (p *CryptoData) ElGamalEncrypt(key *ElGamalPublicKey) *CryptoData {
	if p.err != nil {
		return p
	}
	out, err := EncryptElGamal(p.data, key)
	return p.setAsymmetricResult(out, err)
}
func (p *CryptoData) ElGamalDecrypt(key *ElGamalPrivateKey) *CryptoData {
	if p.err != nil {
		return p
	}
	out, err := DecryptElGamal(p.data, key)
	return p.setAsymmetricResult(out, err)
}
func (p *CryptoData) setAsymmetricResult(out []byte, err error) *CryptoData {
	if err != nil {
		return p.fail(err)
	}
	p.data = out
	return p
}
