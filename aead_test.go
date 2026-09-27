package cryptoutils_test

import (
	"bytes"
	"testing"
	c "www.gitlablow.com/wave4y/cryptoutils"
)

func TestAdditionalAEAD(t *testing.T) {
	for _, alg := range []string{"aes-gcm", "sm4-gcm", "aes-ccm", "sm4-ccm", "chacha20-poly1305", "xchacha20-poly1305"} {
		key := bytes.Repeat([]byte{7}, 32)
		if alg == "sm4-gcm" || alg == "sm4-ccm" {
			key = key[:16]
		}
		for _, pt := range [][]byte{nil, []byte("hello 世界"), bytes.Repeat([]byte{4}, 48)} {
			out, e := c.EncryptAEAD(alg, pt, key, []byte("context"))
			if e != nil {
				t.Fatalf("%s: %v", alg, e)
			}
			plain, e := c.DecryptAEAD(alg, out, key, []byte("context"))
			if e != nil || !bytes.Equal(plain, pt) {
				t.Fatal(alg, e)
			}
			for i := range out {
				changed := append([]byte{}, out...)
				changed[i] ^= 1
				if p, e := c.DecryptAEAD(alg, changed, key, []byte("context")); e == nil || p != nil {
					t.Fatalf("%s tamper %d", alg, i)
				}
			}
			if _, e := c.DecryptAEAD(alg, out, key, nil); e == nil {
				t.Fatal("wrong aad accepted")
			}
		}
	}
}
