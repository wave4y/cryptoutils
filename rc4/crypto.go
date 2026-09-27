package utils

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
)

func Md5Encode(plain string) string {
	h := md5.New()
	h.Write([]byte(plain))
	cipherStr := h.Sum(nil)
	return hex.EncodeToString(cipherStr)
}

func Base64Encode(plain string) string {
	cipher := base64.StdEncoding.EncodeToString([]byte(plain))
	return string(cipher)
}

func Base64Decode(cipher string) (string, error) {
	plain, err := base64.StdEncoding.DecodeString(cipher)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func HexEncode(plain string) string {
	return hex.EncodeToString([]byte(plain))
}

// HexDecodeE decodes hexadecimal text, returning an error for invalid input.
func HexDecodeE(cipher string) (string, error) {
	plain, err := hex.DecodeString(cipher)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// HexDecode decodes hexadecimal text and returns an empty string on error.
//
// Deprecated: Use HexDecodeE to check decoding errors.
func HexDecode(cipher string) string {
	plain, _ := HexDecodeE(cipher)
	return plain
}

// UrlEncode escapes a string for use in a URL query.
func UrlEncode(plain string) string {
	return url.QueryEscape(plain)
}

// UrlDncode is the original misspelled alias for UrlEncode.
//
// Deprecated: Use UrlEncode.
func UrlDncode(plain string) string {
	return UrlEncode(plain)
}

func UrlDecode(cipher string) (string, error) {
	plain, err := url.QueryUnescape(cipher)
	if err != nil {
		return "", err
	}
	return plain, nil
}

const randomAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// RandomStringE returns l uniformly distributed alphanumeric characters using
// crypto/rand. A negative length or random source failure returns an error.
func RandomStringE(l int) (string, error) {
	return randomStringFromReader(l, rand.Reader)
}

func randomStringFromReader(l int, source io.Reader) (string, error) {
	if l < 0 {
		return "", fmt.Errorf("random string: length must be non-negative")
	}
	result := make([]byte, l)
	var buffer [128]byte
	// Reject the incomplete range so every character has equal probability.
	const limit = 256 - 256%len(randomAlphabet)
	for written := 0; written < l; {
		count := l - written
		if count > len(buffer) {
			count = len(buffer)
		}
		if _, err := io.ReadFull(source, buffer[:count]); err != nil {
			return "", fmt.Errorf("random string: %w", err)
		}
		for _, value := range buffer[:count] {
			if int(value) >= limit {
				continue
			}
			result[written] = randomAlphabet[int(value)%len(randomAlphabet)]
			written++
		}
	}
	return string(result), nil
}

// RandomString returns a random alphanumeric string, or an empty string on error.
//
// Deprecated: Use RandomStringE to check length and random source errors.
func RandomString(l int) string {
	result, _ := RandomStringE(l)
	return result
}

// RC4Encrypt encrypts plaintext and returns lowercase hexadecimal ciphertext.
// RC4 is insecure and is retained only for legacy protocols and CTF use.
//
// Deprecated: Use the root package's AES-GCM API for new applications.
func RC4Encrypt(plain string, key []byte) (string, error) {
	src := []byte(plain)
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return "", err
	}
	dst := make([]byte, len(src))
	cipher.XORKeyStream(dst, src)
	return hex.EncodeToString(dst), nil
}

// RC4Decrypt decrypts hexadecimal RC4 ciphertext. RC4 provides no authentication:
// a wrong key or validly encoded tampering cannot be detected.
//
// Deprecated: Use the root package's AES-GCM API for new applications.
func RC4Decrypt(encoded string, key []byte) (string, error) {
	src, err := hex.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return "", err
	}
	dst := make([]byte, len(src))
	cipher.XORKeyStream(dst, src)
	return string(dst), nil
}

// Rc4Encrypt encrypts using RC4 and returns an empty string on error.
//
// Deprecated: Use RC4Encrypt for legacy protocols, or AES-GCM for new applications.
func Rc4Encrypt(plain string, key []byte) string {
	result, _ := RC4Encrypt(plain, key)
	return result
}

// Rc4Decrypt decrypts hexadecimal RC4 ciphertext and returns an empty string on error.
//
// Deprecated: Use RC4Decrypt for legacy protocols, or AES-GCM for new applications.
func Rc4Decrypt(encoded string, key []byte) string {
	result, _ := RC4Decrypt(encoded, key)
	return result
}
