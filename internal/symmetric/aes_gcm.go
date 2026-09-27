package symmetric

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// EncryptAESGCM encrypts and authenticates plaintext with a 16, 24, or 32 byte
// key. The returned envelope is a random 12 byte nonce followed by ciphertext
// and the 16 byte authentication tag. aad is authenticated but is not included
// in the envelope; the same aad must be provided when decrypting.
// Never encrypt more than 2^32 messages with the same key.
func EncryptAESGCM(plaintext, key, aad []byte) ([]byte, error) {
	aead, err := newAESGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("cryptoutils: generate AES-GCM nonce: %w", err)
	}
	return aead.Seal(nonce, nonce, plaintext, aad), nil
}

// DecryptAESGCM authenticates and decrypts an envelope produced by
// EncryptAESGCM. Invalid envelopes, keys, or authentication tags return an error
// without returning plaintext.
func DecryptAESGCM(envelope, key, aad []byte) ([]byte, error) {
	aead, err := newAESGCM(key)
	if err != nil {
		return nil, err
	}
	if len(envelope) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("cryptoutils: invalid AES-GCM envelope")
	}
	plaintext, err := aead.Open(nil, envelope[:aead.NonceSize()], envelope[aead.NonceSize():], aad)
	if err != nil {
		return nil, fmt.Errorf("cryptoutils: AES-GCM authentication failed: %w", err)
	}
	return plaintext, nil
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cryptoutils: AES-GCM key: %w", err)
	}
	return cipher.NewGCM(block)
}
