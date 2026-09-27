package cryptoutils_test

import (
	"bytes"
	"encoding/hex"
	c "github.com/wave4y/cryptoutils"
	"testing"
)

func TestCCMRFC3610(t *testing.T) {
	key := hx("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf")
	nonce := hx("00000003020100a0a1a2a3a4a5")
	aad := hx("0001020304050607")
	pt := hx("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e")
	want := "588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0"
	out, e := c.SealCCM("aes", pt, key, nonce, aad, 8)
	if e != nil || hex.EncodeToString(out) != want {
		t.Fatalf("RFC3610 %x %v", out, e)
	}
	plain, e := c.OpenCCM("aes", out, key, nonce, aad, 8)
	if e != nil || !bytes.Equal(plain, pt) {
		t.Fatal(e)
	}
	out[0] ^= 1
	if plain, e := c.OpenCCM("aes", out, key, nonce, aad, 8); e == nil || plain != nil {
		t.Fatal("tampering accepted")
	}
}
