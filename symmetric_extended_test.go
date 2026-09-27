package cryptoutils_test

import (
	"bytes"
	"encoding/hex"
	"testing"
	c "www.gitlablow.com/wave4y/cryptoutils"
)

func hx(s string) []byte {
	v, e := hex.DecodeString(s)
	if e != nil {
		panic(e)
	}
	return v
}
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

func TestNewCryptoChainContracts(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	iv := bytes.Repeat([]byte{8}, 16)
	p := c.Init("abc")
	p.SetKey(key)
	if got, err := p.SM4CBCEncrypt(iv).Hex().HexDecode().SM4CBCDecrypt(iv).Result(); err != nil || string(got) != "abc" {
		t.Fatal("SM4 chain", err)
	}
	if got, err := p.Reset().ZUCEncrypt(iv).ZUCDecrypt(iv).Result(); err != nil || string(got) != "abc" {
		t.Fatal("ZUC chain", err)
	}
	tag, err := c.ZUCMAC([]byte("abc"), key, iv, 4)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := p.Reset().ZUCMAC(iv, 4).Result(); err != nil || string(got) != hex.EncodeToString(tag) {
		t.Fatal("MAC chain", err)
	}
	if got, err := p.Reset().SM4CCMEncrypt(nil).SM4CCMDecrypt(nil).Result(); err != nil || string(got) != "abc" {
		t.Fatal("CCM chain", err)
	}
	for _, f := range []func(*c.CryptoData) *c.CryptoData{
		func(p *c.CryptoData) *c.CryptoData { return p.BlockEncrypt("sm4", "cbc", iv) },
		func(p *c.CryptoData) *c.CryptoData { return p.BlockDecrypt("aes", "cbc", iv) },
		func(p *c.CryptoData) *c.CryptoData { return p.AEADEncrypt("sm4-gcm", nil) },
		func(p *c.CryptoData) *c.CryptoData { return p.XTSEncrypt("aes", 0) },
		func(p *c.CryptoData) *c.CryptoData { return p.ZUCEncrypt(iv) },
		func(p *c.CryptoData) *c.CryptoData { return p.ZUCMAC(iv, 4) },
		func(p *c.CryptoData) *c.CryptoData { return p.SM2Encrypt(nil) },
	} {
		bad := c.Init(123)
		first := bad.Err()
		if got := f(bad); got.Err() != first || got.Bytes() != nil {
			t.Fatal("error overwritten")
		}
	}
	private, err := c.GenerateSM2Key()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := c.Init("message").SM2Sign(private, nil).Result()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := c.Init("message").SM2Verify(&private.PublicKey, nil, sig).Result(); err != nil || string(got) != "message" {
		t.Fatal("SM2 verify", err)
	}
	if got, err := c.Init("wrong").SM2Verify(&private.PublicKey, nil, sig).Result(); err == nil || got != nil {
		t.Fatal("SM2 failure leaked data")
	}
	if got, err := c.Init("message").SM2Encrypt(&private.PublicKey).SM2Decrypt(private).Result(); err != nil || string(got) != "message" {
		t.Fatal("SM2 chain", err)
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
