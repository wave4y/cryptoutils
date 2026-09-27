package cryptoutils_test

import (
	"encoding/base64"
	"errors"
	"testing"
	c "www.gitlablow.com/wave4y/cryptoutils"
)

func TestReadResultsAndReset(t *testing.T) {
	p := c.Init("abc").Md5()
	const want = "900150983cd24fb0d6963f7d28e17f72"
	for i := 0; i < 3; i++ {
		if p.String() != want || string(p.Bytes()) != want {
			t.Fatalf("read changed result: %q", p.String())
		}
	}
	result, err := p.Result()
	if err != nil || string(result) != want {
		t.Fatalf("Result = %q, %v", result, err)
	}
	result[0] = 'x'
	if p.String() != want {
		t.Fatal("Result aliases internal data")
	}
	if p.Reset().String() != "abc" {
		t.Fatal("Reset did not restore source")
	}
	if got := p.Hex().String(); got != "616263" {
		t.Fatalf("Hex = %q", got)
	}
	if got := p.Base64Encode().String(); got != "NjE2MjYz" {
		t.Fatalf("reading reset the chain: %q", got)
	}
}

func TestInputAndOutputOwnership(t *testing.T) {
	src := []byte("abc")
	p := c.Init(src)
	src[0] = 'x'
	out := p.Bytes()
	out[1] = 'x'
	if p.String() != "abc" || p.Reset().String() != "abc" {
		t.Fatal("input/output aliases chain")
	}
	key := []byte("0123456789abcdef")
	p.SetKey(key)
	key[0] ^= 1
	encrypted, err := p.AESGCMEncrypt(nil).Result()
	if err != nil {
		t.Fatal(err)
	}
	plain, err := c.DecryptAESGCM(encrypted, []byte("0123456789abcdef"), nil)
	if err != nil || string(plain) != "abc" {
		t.Fatalf("SetKey did not copy key: %q, %v", plain, err)
	}
}

func TestInitValidation(t *testing.T) {
	for _, input := range []interface{}{nil, []byte(nil), "", []byte{}} {
		p := c.Init(input)
		if p.Err() != nil || p.String() != "" {
			t.Fatalf("empty input %T: %v", input, p.Err())
		}
	}
	for _, input := range []interface{}{123, struct{}{}, true} {
		p := c.Init(input).Sha256()
		if !errors.Is(p.Err(), c.ErrUnsupportedInput) {
			t.Fatalf("input %T: %v", input, p.Err())
		}
		if data, err := p.Result(); data != nil || err == nil {
			t.Fatal("invalid input returned data")
		}
		if !errors.Is(p.Reset().Err(), c.ErrUnsupportedInput) {
			t.Fatal("Reset cleared invalid initialization")
		}
	}
}

func TestStickyErrors(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		fail        func(*c.CryptoData) *c.CryptoData
	}{
		{"base64", "YWJj!", (*c.CryptoData).Base64Decode},
		{"hex", "6162!", (*c.CryptoData).HexDecode},
		{"odd hex", "a", (*c.CryptoData).HexDecode},
		{"hash", "abc", func(p *c.CryptoData) *c.CryptoData { return p.Hash("sha265") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.fail(c.Init(tc.input))
			first := p.Err()
			if first == nil {
				t.Fatal("invalid input accepted")
			}
			p.Hex().Base64Encode().Base64Decode().Md5().HMACSHA256([]byte("key"))
			p.SetKey([]byte("0123456789abcdef"))
			p.AESGCMEncrypt(nil).AESGCMDecrypt(nil).DesCBCEncrypt().DesDecrypt().DesDecryptLegacy()
			if p.Err() != first || p.String() != "" || p.Bytes() != nil {
				t.Fatal("failed chain continued or lost error")
			}
			if _, err := p.Result(); err != first {
				t.Fatal("Result lost error")
			}
			if p.Reset().Err() != nil || p.String() != tc.input {
				t.Fatal("Reset did not recover source")
			}
		})
	}
	p := c.Init("YWJj!").Base64Decode()
	var corrupt base64.CorruptInputError
	if !errors.As(p.Err(), &corrupt) {
		t.Fatalf("decode error not wrapped: %v", p.Err())
	}
	if !errors.Is(c.Init("abc").Hash("unknown").Err(), c.ErrUnsupportedHash) {
		t.Fatal("missing unsupported hash error")
	}
}
