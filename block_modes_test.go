package cryptoutils_test

import (
	"bytes"
	"encoding/hex"
	c "github.com/wave4y/cryptoutils"
	"testing"
)

func TestAdditionalBlockVectors(t *testing.T) {
	for _, tt := range []struct{ name, key, pt, ct string }{
		{"idea", "00010002000300040005000600070008", "0000000100020003", "11fbed2b01986de5"},
		{"tea", "00000000000000000000000000000000", "0000000000000000", "41ea3a0a94baa940"},
		{"xtea", "00000000000000000000000000000000", "0000000000000000", "dee9d4d8f7131ed9"},
		{"blowfish", "0000000000000000", "0000000000000000", "4ef997456198dd78"},
		{"twofish", "00000000000000000000000000000000", "00000000000000000000000000000000", "9f589f5cf6122c32b6bfec2f2ae8c35a"},
		{"cast5", "0123456712345678234567893456789a", "0123456789abcdef", "238b4fe5847e44b2"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b, e := c.NewBlockCipher(tt.name, hx(tt.key))
			if e != nil {
				t.Fatal(e)
			}
			out := make([]byte, b.BlockSize())
			b.Encrypt(out, hx(tt.pt))
			if hex.EncodeToString(out) != tt.ct {
				t.Fatalf("got %x want %s", out, tt.ct)
			}
			b.Decrypt(out, out)
			if hex.EncodeToString(out) != tt.pt {
				t.Fatalf("decrypt %x", out)
			}
		})
	}
}

func TestAdditionalBlockModes(t *testing.T) {
	for _, alg := range []string{"aes", "sm4", "des", "3des", "blowfish", "twofish", "tea", "xtea", "cast5", "idea"} {
		key := bytes.Repeat([]byte{3}, 16)
		if alg == "des" {
			key = key[:8]
		}
		if alg == "3des" {
			key = bytes.Repeat([]byte{3}, 24)
		}
		b, e := c.NewBlockCipher(alg, key)
		if e != nil {
			t.Fatal(e)
		}
		for _, mode := range []string{"CBC", "CTR", "CFB", "OFB", "ECB"} {
			iv := make([]byte, b.BlockSize())
			if mode == "ECB" {
				iv = nil
			}
			for _, data := range [][]byte{nil, []byte("abc"), bytes.Repeat([]byte{255}, 53)} {
				out, e := c.EncryptBlock(alg, mode, data, key, iv)
				if e != nil {
					t.Fatal(e)
				}
				plain, e := c.DecryptBlock(alg, mode, out, key, iv)
				if e != nil || !bytes.Equal(plain, data) {
					t.Fatalf("%s/%s: %x %v", alg, mode, plain, e)
				}
			}
		}
	}
	key := hx("2b7e151628aed2a6abf7158809cf4f3c")
	iv := hx("000102030405060708090a0b0c0d0e0f")
	pt := hx("6bc1bee22e409f96e93d7e117393172a")
	out, e := c.EncryptBlockRaw("aes", "cbc", pt, key, iv)
	if e != nil || hex.EncodeToString(out) != "7649abac8119b246cee98e9b12e9197d" {
		t.Fatalf("NIST CBC %x %v", out, e)
	}
	if _, e := c.EncryptBlock("aes", "cbc", pt, key, nil); e == nil {
		t.Fatal("missing IV accepted")
	}
	if _, e := c.DecryptBlock("aes", "cbc", []byte{1}, key, iv); e == nil {
		t.Fatal("short ciphertext accepted")
	}
	if _, e := c.EncryptBlock("aes", "unknown", pt, key, iv); e == nil {
		t.Fatal("unknown mode accepted")
	}
}
