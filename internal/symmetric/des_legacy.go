package symmetric

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
//
// Deprecated: DES has only 56 bits of effective key strength. Use
// EncryptAESGCM for new data. This format differs from the old raw CBC format.
func DesCBCEncrypt(data, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cryptoutils: DES key: %w", err)
	}
	padded, err := PKCS7Padding(data, des.BlockSize)
	if err != nil {
		return nil, err
	}
	dataStart := len(desEnvelopePrefix) + des.BlockSize
	tagStart := dataStart + len(padded)
	envelope := make([]byte, tagStart+sha256.Size)
	copy(envelope, desEnvelopePrefix)
	iv := envelope[len(desEnvelopePrefix):dataStart]
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("cryptoutils: generate DES IV: %w", err)
	}
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(envelope[dataStart:tagStart], padded)
	mac := hmac.New(sha256.New, desMACKey(key))
	mac.Write(envelope[:tagStart])
	copy(envelope[tagStart:], mac.Sum(nil))
	return envelope, nil
}

// DesDecrypt verifies and decrypts an envelope produced by DesCBCEncrypt.
// It never falls back to the old unauthenticated raw CBC format.
//
// Deprecated: use DecryptAESGCM for new data. DES has only 56 bits of effective
// key strength, even when its ciphertext is authenticated.
func DesDecrypt(data, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cryptoutils: DES key: %w", err)
	}
	dataStart := len(desEnvelopePrefix) + des.BlockSize
	if len(data) < dataStart+des.BlockSize+sha256.Size || !bytes.Equal(data[:len(desEnvelopePrefix)], []byte(desEnvelopePrefix)) {
		return nil, errDESEnvelope
	}
	tagStart := len(data) - sha256.Size
	if (tagStart-dataStart)%des.BlockSize != 0 {
		return nil, errDESEnvelope
	}
	mac := hmac.New(sha256.New, desMACKey(key))
	mac.Write(data[:tagStart])
	if !hmac.Equal(data[tagStart:], mac.Sum(nil)) {
		return nil, errDESEnvelope
	}
	plaintext := make([]byte, tagStart-dataStart)
	cipher.NewCBCDecrypter(block, data[len(desEnvelopePrefix):dataStart]).CryptBlocks(plaintext, data[dataStart:tagStart])
	plaintext, err = PKCS7UnPadding(plaintext, des.BlockSize)
	if err != nil {
		return nil, errDESEnvelope
	}
	return plaintext, nil
}

// DesDecryptLegacy decrypts the old raw DES-CBC format, which used the key as
// its IV. It checks lengths and padding but cannot detect all tampering or a
// wrong key. Only use it to migrate trusted existing ciphertext.
//
// Deprecated: migrate old data to AES-GCM. This format is unauthenticated and
// DES has only 56 bits of effective key strength.
func DesDecryptLegacy(data, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cryptoutils: DES key: %w", err)
	}
	if len(data) == 0 || len(data)%des.BlockSize != 0 {
		return nil, errors.New("cryptoutils: invalid legacy DES ciphertext length")
	}
	plaintext := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, key).CryptBlocks(plaintext, data)
	plaintext, err = PKCS7UnPadding(plaintext, des.BlockSize)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func desMACKey(key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(desMACDomain))
	return mac.Sum(nil)
}
