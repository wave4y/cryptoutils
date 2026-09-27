package cryptoutils_test

import (
	c "github.com/wave4y/cryptoutils"
	"github.com/wave4y/cryptoutils/utils"
	"testing"
)

func TestUtilsCompatibility(t *testing.T) {
	var p *c.CryptoData = utils.Init("abc")
	if p.Sm3().String() != c.Init("abc").Sm3().String() {
		t.Fatal("utils did not delegate")
	}
	padded, err := utils.PKCS7Padding([]byte("abc"), 16)
	if err != nil {
		t.Fatal(err)
	}
	out, err := utils.PKCS7UnPadding(padded, 16)
	if err != nil || string(out) != "abc" {
		t.Fatalf("PKCS7 wrappers: %q, %v", out, err)
	}
	out, err = utils.PKCS5UnPadding(utils.PKCS5Padding([]byte("abc"), 8))
	if err != nil || string(out) != "abc" {
		t.Fatalf("PKCS5 wrappers: %q, %v", out, err)
	}
	if _, err := utils.Init("?").Base64Decode().Result(); err == nil {
		t.Fatal("utils swallowed error")
	}
}
