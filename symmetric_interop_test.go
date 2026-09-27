package cryptoutils_test

import (
	"bytes"
	"encoding/hex"
	"testing"
	c "www.gitlablow.com/wave4y/cryptoutils"
)

// Independent fixtures produced with Python cryptography/OpenSSL AESCCM and XTS.
func TestCCMAndXTSIndependentFixtures(t *testing.T) {
	pt := make([]byte, 31)
	for i := range pt {
		pt[i] = byte(i)
	}
	out, err := c.SealCCM("aes", pt, make([]byte, 16), make([]byte, 12), make([]byte, 0xff00), 16)
	if err != nil || hex.EncodeToString(out) != "6ec65db1e6b1814116d4c1b39b1c9cb523da74815f836ace8d866238103dadbd640706ea0f1c0634d2744059cd02f9" {
		t.Fatalf("long AAD CCM %x %v", out, err)
	}
	out, err = c.SealCCM("aes", nil, make([]byte, 16), make([]byte, 7), nil, 4)
	if err != nil || hex.EncodeToString(out) != "5863e479" {
		t.Fatalf("empty CCM %x %v", out, err)
	}
	key := make([]byte, 32)
	pt = make([]byte, 64)
	for i := range key {
		key[i] = byte(i)
	}
	for i := range pt {
		pt[i] = byte(i)
	}
	out, err = c.EncryptXTS("aes", pt, key, 42)
	if err != nil || hex.EncodeToString(out) != "b18dde37630c994c64f291b47657c66b3fe9d89c784c6c98828e3e3f5fd9658caabb1b00a1137e6b7036477bc9edec907a096813a18e3e1bff0dfd2eccac6fe7" {
		t.Fatalf("XTS %x %v", out, err)
	}
	plain, err := c.DecryptXTS("aes", out, key, 42)
	if err != nil || !bytes.Equal(plain, pt) {
		t.Fatal("XTS decrypt", err)
	}
	wrong, _ := c.DecryptXTS("aes", out, key, 43)
	if bytes.Equal(wrong, pt) {
		t.Fatal("sector ignored")
	}
	for _, bad := range [][]byte{nil, make([]byte, 1), make([]byte, 15), make([]byte, 17)} {
		if _, err := c.EncryptXTS("aes", bad, key, 0); err == nil {
			t.Fatal("XTS bad length")
		}
	}
	if _, err := c.EncryptXTS("aes", pt, make([]byte, 32), 0); err == nil {
		t.Fatal("XTS duplicate key halves")
	}
	if _, err := c.SealCCM("aes", make([]byte, 65536), make([]byte, 16), make([]byte, 13), nil, 16); err == nil {
		t.Fatal("CCM length overflow")
	}
	for _, n := range []int{6, 14} {
		if _, err := c.SealCCM("aes", nil, make([]byte, 16), make([]byte, n), nil, 16); err == nil {
			t.Fatal("bad nonce")
		}
	}
	for _, n := range []int{0, 3, 5, 18} {
		if _, err := c.OpenCCM("aes", make([]byte, 32), make([]byte, 16), make([]byte, 12), nil, n); err == nil {
			t.Fatal("bad tag")
		}
	}
}

func TestIDEAIndependentFixturesAndCMAC64(t *testing.T) {
	for _, tc := range []struct{ k, p, w string }{
		{"00000000000000000000000000000000", "0000000000000000", "0001000100000000"},
		{"000102030405060708090a0b0c0d0e0f", "0001020304050607", "864c9d7d208a0e65"},
	} {
		b, err := c.NewBlockCipher("idea", hx(tc.k))
		if err != nil {
			t.Fatal(err)
		}
		v := hx(tc.p)
		b.Encrypt(v, v)
		if hex.EncodeToString(v) != tc.w {
			t.Fatalf("IDEA %x", v)
		}
		b.Decrypt(v, v)
		if !bytes.Equal(v, hx(tc.p)) {
			t.Fatal("IDEA inverse")
		}
	}
	key := make([]byte, 24)
	msg := make([]byte, 21)
	for i := range key {
		key[i] = byte(i)
	}
	for i := range msg {
		msg[i] = byte(i)
	}
	tag, err := c.CMAC("3des", msg, key)
	if err != nil || hex.EncodeToString(tag) != "4a9ab5894d652136" {
		t.Fatalf("CMAC64 %x %v", tag, err)
	}
	ok, err := c.VerifyCMAC("3des", msg, key, tag)
	if err != nil || !ok {
		t.Fatal(err)
	}
	tag[0] ^= 1
	if ok, _ := c.VerifyCMAC("3des", msg, key, tag); ok {
		t.Fatal("MAC tamper")
	}
	b, _ := c.NewBlockCipher("idea", make([]byte, 16))
	for _, f := range []func(){func() { b.Encrypt(nil, make([]byte, 8)) }, func() { b.Decrypt(make([]byte, 8), nil) }, func() { v := make([]byte, 9); b.Encrypt(v[1:], v[:8]) }, func() { v := make([]byte, 9); b.Decrypt(v[:8], v[1:]) }} {
		func() {
			defer func() {
				if recover() == nil {
					t.Error("expected block panic")
				}
			}()
			f()
		}()
	}
}
