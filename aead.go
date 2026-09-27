package cryptoutils

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

// EncryptAEAD encrypts using aes-gcm, sm4-gcm, aes-ccm, sm4-ccm,
// chacha20-poly1305 or xchacha20-poly1305. Output is nonce || ciphertext || tag.
// AAD is not included. Random 12-byte nonces require key rotation before 2^32 messages.
func EncryptAEAD(algorithm string, data, key, aad []byte) ([]byte, error) {
	name := strings.ToLower(algorithm)
	if name == "aes-ccm" || name == "sm4-ccm" {
		nonce := make([]byte, 12)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
		out, err := SealCCM(strings.TrimSuffix(name, "-ccm"), data, key, nonce, aad, 16)
		if err != nil {
			return nil, err
		}
		return append(nonce, out...), nil
	}
	a, err := newNamedAEAD(name, key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, a.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	return a.Seal(nonce, nonce, data, aad), nil
}

// DecryptAEAD verifies authentication before returning any plaintext.
func DecryptAEAD(algorithm string, data, key, aad []byte) ([]byte, error) {
	name := strings.ToLower(algorithm)
	if name == "aes-ccm" || name == "sm4-ccm" {
		if len(data) < 28 {
			return nil, fmt.Errorf("cryptoutils: invalid CCM envelope")
		}
		return OpenCCM(strings.TrimSuffix(name, "-ccm"), data[12:], key, data[:12], aad, 16)
	}
	a, err := newNamedAEAD(name, key)
	if err != nil {
		return nil, err
	}
	if len(data) < a.NonceSize()+a.Overhead() {
		return nil, fmt.Errorf("cryptoutils: invalid AEAD envelope")
	}
	out, err := a.Open(nil, data[:a.NonceSize()], data[a.NonceSize():], aad)
	if err != nil {
		return nil, fmt.Errorf("cryptoutils: authentication failed: %w", err)
	}
	return out, nil
}
func newNamedAEAD(name string, key []byte) (cipher.AEAD, error) {
	switch name {
	case "aes-gcm", "sm4-gcm":
		b, err := NewBlockCipher(strings.TrimSuffix(name, "-gcm"), key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(b)
	case "chacha20-poly1305":
		return chacha20poly1305.New(key)
	case "xchacha20-poly1305":
		return chacha20poly1305.NewX(key)
	default:
		return nil, fmt.Errorf("cryptoutils: unsupported AEAD %q", name)
	}
}
func (p *CryptoData) AEADEncrypt(algorithm string, aad []byte) *CryptoData {
	if p.err != nil {
		return p
	}
	out, err := EncryptAEAD(algorithm, p.data, p.key, aad)
	if err != nil {
		return p.fail(err)
	}
	p.data = out
	return p
}
func (p *CryptoData) AEADDecrypt(algorithm string, aad []byte) *CryptoData {
	if p.err != nil {
		return p
	}
	out, err := DecryptAEAD(algorithm, p.data, p.key, aad)
	if err != nil {
		return p.fail(err)
	}
	p.data = out
	return p
}
func (p *CryptoData) SM4GCMEncrypt(aad []byte) *CryptoData { return p.AEADEncrypt("sm4-gcm", aad) }
func (p *CryptoData) SM4GCMDecrypt(aad []byte) *CryptoData { return p.AEADDecrypt("sm4-gcm", aad) }
func (p *CryptoData) ChaCha20Poly1305Encrypt(aad []byte) *CryptoData {
	return p.AEADEncrypt("chacha20-poly1305", aad)
}
func (p *CryptoData) ChaCha20Poly1305Decrypt(aad []byte) *CryptoData {
	return p.AEADDecrypt("chacha20-poly1305", aad)
}
func (p *CryptoData) XChaCha20Poly1305Encrypt(aad []byte) *CryptoData {
	return p.AEADEncrypt("xchacha20-poly1305", aad)
}
func (p *CryptoData) XChaCha20Poly1305Decrypt(aad []byte) *CryptoData {
	return p.AEADDecrypt("xchacha20-poly1305", aad)
}
