package cryptoutils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"fmt"
	"strings"

	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/cast5"
	"golang.org/x/crypto/tea"
	"golang.org/x/crypto/twofish"
	"golang.org/x/crypto/xtea"
	"golang.org/x/crypto/xts"
	"www.gitlablow.com/wave4y/cryptoutils/internal/idea"
	"www.gitlablow.com/wave4y/cryptoutils/sm4"
)

// NewBlockCipher constructs AES, SM4, DES, 3DES, Blowfish, Twofish, TEA, XTEA,
// CAST5 or IDEA. Legacy ciphers are provided for interoperability, not as defaults.
func NewBlockCipher(algorithm string, key []byte) (cipher.Block, error) {
	switch strings.ToLower(strings.ReplaceAll(algorithm, "-", "")) {
	case "aes":
		return aes.NewCipher(key)
	case "sm4":
		return sm4.NewCipher(key)
	case "des":
		return des.NewCipher(key)
	case "3des", "tripledes":
		return des.NewTripleDESCipher(key)
	case "blowfish":
		return blowfish.NewCipher(key)
	case "twofish":
		return twofish.NewCipher(key)
	case "tea":
		return tea.NewCipher(key)
	case "xtea":
		return xtea.NewCipher(key)
	case "cast5", "cast128":
		return cast5.NewCipher(key)
	case "idea":
		return idea.NewCipher(key)
	default:
		return nil, fmt.Errorf("cryptoutils: unsupported block cipher %q", algorithm)
	}
}

// EncryptBlock encrypts raw protocol data. CBC/ECB use PKCS7 padding; CTR/CFB/OFB
// do not pad. IV must be one block for non-ECB modes and empty for ECB. The IV
// is NOT prepended and no authentication is provided. Prefer an AEAD for new data.
func EncryptBlock(algorithm, mode string, data, key, iv []byte) ([]byte, error) {
	return cryptBlockMode(algorithm, mode, data, key, iv, false, true)
}

// DecryptBlock reverses EncryptBlock; it cannot detect all tampering or wrong keys.
func DecryptBlock(algorithm, mode string, data, key, iv []byte) ([]byte, error) {
	return cryptBlockMode(algorithm, mode, data, key, iv, true, true)
}

// EncryptBlockRaw is EncryptBlock without padding. CBC/ECB require whole blocks.
func EncryptBlockRaw(algorithm, mode string, data, key, iv []byte) ([]byte, error) {
	return cryptBlockMode(algorithm, mode, data, key, iv, false, false)
}

// DecryptBlockRaw is DecryptBlock without unpadding.
func DecryptBlockRaw(algorithm, mode string, data, key, iv []byte) ([]byte, error) {
	return cryptBlockMode(algorithm, mode, data, key, iv, true, false)
}
func cryptBlockMode(algorithm, mode string, data, key, iv []byte, decrypt, pad bool) ([]byte, error) {
	b, err := NewBlockCipher(algorithm, key)
	if err != nil {
		return nil, err
	}
	mode = strings.ToUpper(mode)
	bs := b.BlockSize()
	switch mode {
	case "ECB":
		if len(iv) != 0 {
			return nil, fmt.Errorf("cryptoutils: ECB does not use an IV")
		}
	case "CBC", "CTR", "CFB", "OFB":
		if len(iv) != bs {
			return nil, fmt.Errorf("cryptoutils: %s IV must be %d bytes", mode, bs)
		}
	default:
		return nil, fmt.Errorf("cryptoutils: unsupported block mode %q", mode)
	}
	if mode == "CBC" || mode == "ECB" {
		if !decrypt && pad {
			data, err = PKCS7Padding(data, bs)
			if err != nil {
				return nil, err
			}
		}
		if len(data)%bs != 0 || (decrypt && pad && len(data) == 0) {
			return nil, fmt.Errorf("cryptoutils: invalid block data length")
		}
	}
	out := make([]byte, len(data))
	switch mode {
	case "ECB":
		for i := 0; i < len(data); i += bs {
			if decrypt {
				b.Decrypt(out[i:], data[i:])
			} else {
				b.Encrypt(out[i:], data[i:])
			}
		}
	case "CBC":
		if decrypt {
			cipher.NewCBCDecrypter(b, iv).CryptBlocks(out, data)
		} else {
			cipher.NewCBCEncrypter(b, iv).CryptBlocks(out, data)
		}
	case "CTR":
		cipher.NewCTR(b, iv).XORKeyStream(out, data)
	case "OFB":
		cipher.NewOFB(b, iv).XORKeyStream(out, data)
	case "CFB":
		if decrypt {
			cipher.NewCFBDecrypter(b, iv).XORKeyStream(out, data)
		} else {
			cipher.NewCFBEncrypter(b, iv).XORKeyStream(out, data)
		}
	}
	if decrypt && pad && (mode == "CBC" || mode == "ECB") {
		return PKCS7UnPadding(out, bs)
	}
	return out, nil
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
	return cryptXTS(algorithm, data, key, sector, false)
}

// DecryptXTS reverses EncryptXTS for the same sector number.
func DecryptXTS(algorithm string, data, key []byte, sector uint64) ([]byte, error) {
	return cryptXTS(algorithm, data, key, sector, true)
}
func cryptXTS(algorithm string, data, key []byte, sector uint64, decrypt bool) ([]byte, error) {
	if len(data) == 0 || len(data)%16 != 0 || len(data) >= 1<<24 {
		return nil, fmt.Errorf("cryptoutils: XTS requires a nonempty whole-block sector shorter than 2^24 bytes")
	}
	if len(key)%2 != 0 {
		return nil, fmt.Errorf("cryptoutils: invalid XTS key length")
	}
	b, err := NewBlockCipher(algorithm, key[:len(key)/2])
	if err != nil {
		return nil, err
	}
	if b.BlockSize() != 16 {
		return nil, fmt.Errorf("cryptoutils: XTS requires a 16-byte block cipher")
	}
	same := true
	for i := 0; i < len(key)/2; i++ {
		if key[i] != key[i+len(key)/2] {
			same = false
			break
		}
	}
	if same {
		return nil, fmt.Errorf("cryptoutils: XTS key halves must differ")
	}
	c, err := xts.NewCipher(func(k []byte) (cipher.Block, error) { return NewBlockCipher(algorithm, k) }, key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	if decrypt {
		c.Decrypt(out, data, sector)
	} else {
		c.Encrypt(out, data, sector)
	}
	return out, nil
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
