package cryptoutils

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

const desEnvelopePrefix = "CU-DES\x01"
const desMACDomain = "cryptoutils/DES-CBC/HMAC-SHA256/v1"

var errDESEnvelope = errors.New("cryptoutils: invalid or unauthenticated DES envelope")

// DesCBCEncrypt produces a versioned authenticated envelope:
// "CU-DES\x01" || random IV (8 bytes) || CBC ciphertext || HMAC-SHA256 (32 bytes).
// The MAC covers the prefix, IV, and ciphertext. The MAC key is derived as
// HMAC-SHA256(key, "cryptoutils/DES-CBC/HMAC-SHA256/v1").
// Read Err or Result to check whether encryption succeeded.
//
// Deprecated: DES has only 56 bits of effective key strength. Use
// AESGCMEncrypt for new data. This format differs from the old raw CBC format.
func (p *CryptoData) DesCBCEncrypt() *CryptoData {
	if p.err != nil {
		return p
	}
	block, err := des.NewCipher(p.key)
	if err != nil {
		return p.fail(fmt.Errorf("cryptoutils: DES key: %w", err))
	}
	padded, err := PKCS7Padding(p.data, des.BlockSize)
	if err != nil {
		return p.fail(err)
	}
	dataStart := len(desEnvelopePrefix) + des.BlockSize
	tagStart := dataStart + len(padded)
	envelope := make([]byte, tagStart+sha256.Size)
	copy(envelope, desEnvelopePrefix)
	iv := envelope[len(desEnvelopePrefix):dataStart]
	if _, err := rand.Read(iv); err != nil {
		return p.fail(fmt.Errorf("cryptoutils: generate DES IV: %w", err))
	}
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(envelope[dataStart:tagStart], padded)
	mac := hmac.New(sha256.New, desMACKey(p.key))
	mac.Write(envelope[:tagStart])
	copy(envelope[tagStart:], mac.Sum(nil))
	p.data = envelope
	return p
}

// DesDecrypt verifies and decrypts an envelope produced by DesCBCEncrypt.
// It never falls back to the old unauthenticated raw CBC format.
//
// Deprecated: use AESGCMDecrypt for new data. DES has only 56 bits of effective
// key strength, even when its ciphertext is authenticated.
func (p *CryptoData) DesDecrypt() *CryptoData {
	if p.err != nil {
		return p
	}
	block, err := des.NewCipher(p.key)
	if err != nil {
		return p.fail(fmt.Errorf("cryptoutils: DES key: %w", err))
	}
	dataStart := len(desEnvelopePrefix) + des.BlockSize
	if len(p.data) < dataStart+des.BlockSize+sha256.Size || !bytes.Equal(p.data[:len(desEnvelopePrefix)], []byte(desEnvelopePrefix)) {
		return p.fail(errDESEnvelope)
	}
	tagStart := len(p.data) - sha256.Size
	if (tagStart-dataStart)%des.BlockSize != 0 {
		return p.fail(errDESEnvelope)
	}
	mac := hmac.New(sha256.New, desMACKey(p.key))
	mac.Write(p.data[:tagStart])
	if !hmac.Equal(p.data[tagStart:], mac.Sum(nil)) {
		return p.fail(errDESEnvelope)
	}
	plaintext := make([]byte, tagStart-dataStart)
	cipher.NewCBCDecrypter(block, p.data[len(desEnvelopePrefix):dataStart]).CryptBlocks(plaintext, p.data[dataStart:tagStart])
	plaintext, err = PKCS7UnPadding(plaintext, des.BlockSize)
	if err != nil {
		return p.fail(errDESEnvelope)
	}
	p.data = plaintext
	return p
}

// DesDecryptLegacy decrypts the old raw DES-CBC format, which used the key as
// its IV. It checks lengths and padding but cannot detect all tampering or a
// wrong key. Only use it to migrate trusted existing ciphertext.
//
// Deprecated: migrate old data to AES-GCM. This format is unauthenticated and
// DES has only 56 bits of effective key strength.
func (p *CryptoData) DesDecryptLegacy() *CryptoData {
	if p.err != nil {
		return p
	}
	block, err := des.NewCipher(p.key)
	if err != nil {
		return p.fail(fmt.Errorf("cryptoutils: DES key: %w", err))
	}
	if len(p.data) == 0 || len(p.data)%des.BlockSize != 0 {
		return p.fail(errors.New("cryptoutils: invalid legacy DES ciphertext length"))
	}
	plaintext := make([]byte, len(p.data))
	cipher.NewCBCDecrypter(block, p.key).CryptBlocks(plaintext, p.data)
	plaintext, err = PKCS7UnPadding(plaintext, des.BlockSize)
	if err != nil {
		return p.fail(err)
	}
	p.data = plaintext
	return p
}

func desMACKey(key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(desMACDomain))
	return mac.Sum(nil)
}
