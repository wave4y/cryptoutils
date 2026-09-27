package cryptoutils

import (
	"crypto/cipher"

	"github.com/wave4y/cryptoutils/internal/symmetric"
)

// EncryptAEAD encrypts using aes-gcm, sm4-gcm, aes-ccm, sm4-ccm,
// chacha20-poly1305 or xchacha20-poly1305. Output is nonce || ciphertext || tag.
// AAD is not included. Random 12-byte nonces require key rotation before 2^32 messages.
func EncryptAEAD(algorithm string, data, key, aad []byte) ([]byte, error) {
	return symmetric.EncryptAEAD(algorithm, data, key, aad)
}

// DecryptAEAD verifies authentication before returning any plaintext.
func DecryptAEAD(algorithm string, data, key, aad []byte) ([]byte, error) {
	return symmetric.DecryptAEAD(algorithm, data, key, aad)
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

// EncryptAESGCM encrypts and authenticates plaintext with a 16, 24, or 32 byte
// key. The returned envelope is a random 12 byte nonce followed by ciphertext
// and the 16 byte authentication tag. aad is authenticated but is not included
// in the envelope; the same aad must be provided when decrypting.
// Never encrypt more than 2^32 messages with the same key.
func EncryptAESGCM(plaintext, key, aad []byte) ([]byte, error) {
	return symmetric.EncryptAESGCM(plaintext, key, aad)
}

// DecryptAESGCM authenticates and decrypts an envelope produced by
// EncryptAESGCM. Invalid envelopes, keys, or authentication tags return an error
// without returning plaintext.
func DecryptAESGCM(envelope, key, aad []byte) ([]byte, error) {
	return symmetric.DecryptAESGCM(envelope, key, aad)
}

// AESGCMEncrypt replaces the current data with a nonce-prefixed AES-GCM
// envelope. Read Err or Result to check whether encryption succeeded.
func (p *CryptoData) AESGCMEncrypt(aad []byte) *CryptoData {
	if p.err != nil {
		return p
	}
	data, err := EncryptAESGCM(p.data, p.key, aad)
	if err != nil {
		return p.fail(err)
	}
	p.data = data
	return p
}

// AESGCMDecrypt authenticates and decrypts the current AES-GCM envelope.
// Read Err or Result to check whether decryption succeeded.
func (p *CryptoData) AESGCMDecrypt(aad []byte) *CryptoData {
	if p.err != nil {
		return p
	}
	data, err := DecryptAESGCM(p.data, p.key, aad)
	if err != nil {
		return p.fail(err)
	}
	p.data = data
	return p
}

// NewBlockCipher constructs AES, SM4, DES, 3DES, Blowfish, Twofish, TEA, XTEA,
// CAST5 or IDEA. Legacy ciphers are provided for interoperability, not as defaults.
func NewBlockCipher(algorithm string, key []byte) (cipher.Block, error) {
	return symmetric.NewBlockCipher(algorithm, key)
}

// EncryptBlock encrypts raw protocol data. CBC/ECB use PKCS7 padding; CTR/CFB/OFB
// do not pad. IV must be one block for non-ECB modes and empty for ECB. The IV
// is NOT prepended and no authentication is provided. Prefer an AEAD for new data.
func EncryptBlock(algorithm, mode string, data, key, iv []byte) ([]byte, error) {
	return symmetric.EncryptBlock(algorithm, mode, data, key, iv)
}

// DecryptBlock reverses EncryptBlock; it cannot detect all tampering or wrong keys.
func DecryptBlock(algorithm, mode string, data, key, iv []byte) ([]byte, error) {
	return symmetric.DecryptBlock(algorithm, mode, data, key, iv)
}

// EncryptBlockRaw is EncryptBlock without padding. CBC/ECB require whole blocks.
func EncryptBlockRaw(algorithm, mode string, data, key, iv []byte) ([]byte, error) {
	return symmetric.EncryptBlockRaw(algorithm, mode, data, key, iv)
}

// DecryptBlockRaw is DecryptBlock without unpadding.
func DecryptBlockRaw(algorithm, mode string, data, key, iv []byte) ([]byte, error) {
	return symmetric.DecryptBlockRaw(algorithm, mode, data, key, iv)
}

// BlockEncrypt uses SetKey and emits raw ciphertext using EncryptBlock's format.
func (p *CryptoData) BlockEncrypt(algorithm, mode string, iv []byte) *CryptoData {
	if p.err != nil {
		return p
	}
	out, err := EncryptBlock(algorithm, mode, p.data, p.key, iv)
	if err != nil {
		return p.fail(err)
	}
	p.data = out
	return p
}

// BlockDecrypt uses SetKey and reverses BlockEncrypt.
func (p *CryptoData) BlockDecrypt(algorithm, mode string, iv []byte) *CryptoData {
	if p.err != nil {
		return p
	}
	out, err := DecryptBlock(algorithm, mode, p.data, p.key, iv)
	if err != nil {
		return p.fail(err)
	}
	p.data = out
	return p
}

// EncryptXTS encrypts whole 16-byte blocks in a disk sector, without authentication
// or ciphertext stealing. The key contains two equal-length cipher keys.
func EncryptXTS(algorithm string, data, key []byte, sector uint64) ([]byte, error) {
	return symmetric.EncryptXTS(algorithm, data, key, sector)
}

// DecryptXTS reverses EncryptXTS for the same sector number.
func DecryptXTS(algorithm string, data, key []byte, sector uint64) ([]byte, error) {
	return symmetric.DecryptXTS(algorithm, data, key, sector)
}

func (p *CryptoData) XTSEncrypt(algorithm string, sector uint64) *CryptoData {
	if p.err != nil {
		return p
	}
	out, err := EncryptXTS(algorithm, p.data, p.key, sector)
	if err != nil {
		return p.fail(err)
	}
	p.data = out
	return p
}

func (p *CryptoData) XTSDecrypt(algorithm string, sector uint64) *CryptoData {
	if p.err != nil {
		return p
	}
	out, err := DecryptXTS(algorithm, p.data, p.key, sector)
	if err != nil {
		return p.fail(err)
	}
	p.data = out
	return p
}

// SealCCM implements RFC 3610 with an explicit nonce for interoperability.
// nonce must have 7..13 bytes and be unique per key. tagSize is even, 4..16.
// Unlike EncryptAEAD, its result does not include the nonce.
func SealCCM(algorithm string, data, key, nonce, aad []byte, tagSize int) ([]byte, error) {
	return symmetric.SealCCM(algorithm, data, key, nonce, aad, tagSize)
}

// OpenCCM authenticates ciphertext and returns no plaintext on failure.
func OpenCCM(algorithm string, data, key, nonce, aad []byte, tagSize int) ([]byte, error) {
	return symmetric.OpenCCM(algorithm, data, key, nonce, aad, tagSize)
}

// CMAC implements NIST SP 800-38B for 64- or 128-bit block ciphers.
func CMAC(algorithm string, data, key []byte) ([]byte, error) {
	return symmetric.CMAC(algorithm, data, key)
}

func VerifyCMAC(algorithm string, data, key, tag []byte) (bool, error) {
	return symmetric.VerifyCMAC(algorithm, data, key, tag)
}

func (p *CryptoData) CMAC(algorithm string) *CryptoData {
	if p.err != nil {
		return p
	}
	out, err := CMAC(algorithm, p.data, p.key)
	if err != nil {
		return p.fail(err)
	}
	p.data = out
	return p.Hex()
}

// Poly1305 computes a raw 16-byte one-time authenticator. Each 32-byte key MUST
// be used for only one message. Prefer ChaCha20-Poly1305 for message encryption.
func Poly1305(data, key []byte) ([]byte, error) {
	return symmetric.Poly1305(data, key)
}

func VerifyPoly1305(data, key, tag []byte) (bool, error) {
	return symmetric.VerifyPoly1305(data, key, tag)
}

func (p *CryptoData) Poly1305(key []byte) *CryptoData {
	if p.err != nil {
		return p
	}
	out, err := Poly1305(p.data, key)
	if err != nil {
		return p.fail(err)
	}
	p.data = out
	return p.Hex()
}

// PKCS7Padding returns a padded copy of src. blockSize must be between 1 and
// 255 bytes. Empty input and input already aligned to a block receive a full
// block of padding.
func PKCS7Padding(src []byte, blockSize int) ([]byte, error) {
	return symmetric.PKCS7Padding(src, blockSize)
}

// PKCS7UnPadding validates every padding byte and returns an unpadded copy.
// src must contain a nonempty whole number of blocks. This function only checks
// padding, not authenticity; authenticate ciphertext before decrypting it.
func PKCS7UnPadding(src []byte, blockSize int) ([]byte, error) {
	return symmetric.PKCS7UnPadding(src, blockSize)
}

// PKCS5Padding returns a padded copy, or nil when blockSize is not 8.
//
// Deprecated: use PKCS7Padding for an explicit error and a configurable block
// size. PKCS#5 padding is defined only for 8 byte blocks.
func PKCS5Padding(src []byte, blockSize int) []byte {
	return symmetric.PKCS5Padding(src, blockSize)
}

// PKCS5UnPadding validates and removes padding for 8 byte blocks.
//
// Deprecated: use PKCS7UnPadding and specify the cipher's block size.
func PKCS5UnPadding(src []byte) ([]byte, error) {
	return symmetric.PKCS5UnPadding(src)
}

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
	out, err := symmetric.DesCBCEncrypt(p.data, p.key)
	if err != nil {
		return p.fail(err)
	}
	p.data = out
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
	out, err := symmetric.DesDecrypt(p.data, p.key)
	if err != nil {
		return p.fail(err)
	}
	p.data = out
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
	out, err := symmetric.DesDecryptLegacy(p.data, p.key)
	if err != nil {
		return p.fail(err)
	}
	p.data = out
	return p
}

// These convenience methods use the same explicit IV and padding conventions as
// BlockEncrypt and BlockDecrypt. The raw modes do not provide authentication.
func (p *CryptoData) AESCBCEncrypt(iv []byte) *CryptoData { return p.BlockEncrypt("aes", "cbc", iv) }

func (p *CryptoData) AESCBCDecrypt(iv []byte) *CryptoData { return p.BlockDecrypt("aes", "cbc", iv) }

func (p *CryptoData) AESCTREncrypt(iv []byte) *CryptoData { return p.BlockEncrypt("aes", "ctr", iv) }

func (p *CryptoData) AESCTRDecrypt(iv []byte) *CryptoData { return p.BlockDecrypt("aes", "ctr", iv) }

func (p *CryptoData) AESCFBEncrypt(iv []byte) *CryptoData { return p.BlockEncrypt("aes", "cfb", iv) }

func (p *CryptoData) AESCFBDecrypt(iv []byte) *CryptoData { return p.BlockDecrypt("aes", "cfb", iv) }

func (p *CryptoData) AESOFBEncrypt(iv []byte) *CryptoData { return p.BlockEncrypt("aes", "ofb", iv) }

func (p *CryptoData) AESOFBDecrypt(iv []byte) *CryptoData { return p.BlockDecrypt("aes", "ofb", iv) }

func (p *CryptoData) AESECBEncrypt() *CryptoData { return p.BlockEncrypt("aes", "ecb", nil) }

func (p *CryptoData) AESECBDecrypt() *CryptoData { return p.BlockDecrypt("aes", "ecb", nil) }

func (p *CryptoData) AESCCMEncrypt(aad []byte) *CryptoData { return p.AEADEncrypt("aes-ccm", aad) }

func (p *CryptoData) AESCCMDecrypt(aad []byte) *CryptoData { return p.AEADDecrypt("aes-ccm", aad) }

func (p *CryptoData) AESXTSEncrypt(sector uint64) *CryptoData { return p.XTSEncrypt("aes", sector) }

func (p *CryptoData) AESXTSDecrypt(sector uint64) *CryptoData { return p.XTSDecrypt("aes", sector) }

func (p *CryptoData) SM4CBCEncrypt(iv []byte) *CryptoData { return p.BlockEncrypt("sm4", "cbc", iv) }

func (p *CryptoData) SM4CBCDecrypt(iv []byte) *CryptoData { return p.BlockDecrypt("sm4", "cbc", iv) }

func (p *CryptoData) SM4CTREncrypt(iv []byte) *CryptoData { return p.BlockEncrypt("sm4", "ctr", iv) }

func (p *CryptoData) SM4CTRDecrypt(iv []byte) *CryptoData { return p.BlockDecrypt("sm4", "ctr", iv) }

func (p *CryptoData) SM4CFBEncrypt(iv []byte) *CryptoData { return p.BlockEncrypt("sm4", "cfb", iv) }

func (p *CryptoData) SM4CFBDecrypt(iv []byte) *CryptoData { return p.BlockDecrypt("sm4", "cfb", iv) }

func (p *CryptoData) SM4OFBEncrypt(iv []byte) *CryptoData { return p.BlockEncrypt("sm4", "ofb", iv) }

func (p *CryptoData) SM4OFBDecrypt(iv []byte) *CryptoData { return p.BlockDecrypt("sm4", "ofb", iv) }

func (p *CryptoData) SM4ECBEncrypt() *CryptoData { return p.BlockEncrypt("sm4", "ecb", nil) }

func (p *CryptoData) SM4ECBDecrypt() *CryptoData { return p.BlockDecrypt("sm4", "ecb", nil) }

func (p *CryptoData) SM4CCMEncrypt(aad []byte) *CryptoData { return p.AEADEncrypt("sm4-ccm", aad) }

func (p *CryptoData) SM4CCMDecrypt(aad []byte) *CryptoData { return p.AEADDecrypt("sm4-ccm", aad) }
