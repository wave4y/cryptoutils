package cryptoutils_test

import (
	"encoding/hex"
	"testing"
	c "www.gitlablow.com/wave4y/cryptoutils"
)

func TestAdditionalMACVectors(t *testing.T) {
	key := hx("2b7e151628aed2a6abf7158809cf4f3c")
	tag, e := c.CMAC("aes", nil, key)
	if e != nil || hex.EncodeToString(tag) != "bb1d6929e95937287fa37d129b756746" {
		t.Fatalf("CMAC %x %v", tag, e)
	}
	tag, e = c.CMAC("aes", hx("6bc1bee22e409f96e93d7e117393172a"), key)
	if e != nil || hex.EncodeToString(tag) != "070a16b46b4d4144f79bdd9dd04a287c" {
		t.Fatalf("CMAC %x %v", tag, e)
	}
	tag, e = c.Poly1305([]byte("Cryptographic Forum Research Group"), hx("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"))
	if e != nil || hex.EncodeToString(tag) != "a8061dc1305136c6c22b8baf0c0127a9" {
		t.Fatalf("Poly1305 %x %v", tag, e)
	}
}
