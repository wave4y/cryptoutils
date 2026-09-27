package cryptoutils_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	c "github.com/wave4y/cryptoutils"
)

func TestKDFKnownVectors(t *testing.T) {
	// PBKDF2 from RFC 6070; HKDF from RFC 5869 A.1; scrypt from RFC 7914.
	// Argon2id vector is from the upstream x/crypto Argon2 reference vectors.
	pbk := c.PBKDF2Options{Hash: "sha1", Iterations: 1, KeyLength: 20}
	hk := c.HKDFOptions{Hash: "sha256", KeyLength: 42}
	sc := c.ScryptOptions{N: 16, R: 1, P: 1, KeyLength: 64}
	ar := c.Argon2idOptions{Time: 1, Memory: 64, Threads: 1, KeyLength: 24}
	fromHex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	secret := bytes.Repeat([]byte{0x0b}, 22)
	salt, info := fromHex("000102030405060708090a0b0c"), fromHex("f0f1f2f3f4f5f6f7f8f9")
	tests := []struct {
		name, want string
		call       func() ([]byte, error)
		chain      func() *c.CryptoData
	}{
		{"PBKDF2", "0c60c80f961f0e71f3a9b524af6012062fe037a6", func() ([]byte, error) { return c.PBKDF2([]byte("password"), []byte("salt"), &pbk) }, func() *c.CryptoData { return c.Init("password").PBKDF2([]byte("salt"), &pbk) }},
		{"HKDF", "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", func() ([]byte, error) { return c.HKDF(secret, salt, info, &hk) }, func() *c.CryptoData { return c.Init(secret).HKDF(salt, info, &hk) }},
		{"scrypt", "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906", func() ([]byte, error) { return c.Scrypt(nil, nil, &sc) }, func() *c.CryptoData { return c.Init(nil).Scrypt(nil, &sc) }},
		{"Argon2id", "655ad15eac652dc59f7170a7332bf49b8469be1fdb9c28bb", func() ([]byte, error) { return c.Argon2id([]byte("password"), []byte("somesalt"), &ar) }, func() *c.CryptoData { return c.Init("password").Argon2id([]byte("somesalt"), &ar) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := tt.call()
			if err != nil || hex.EncodeToString(out) != tt.want {
				t.Fatalf("got %x, %v", out, err)
			}
			p := tt.chain()
			if p.Err() != nil || p.Hex().String() != tt.want {
				t.Fatalf("chain: %s %v", p.String(), p.Err())
			}
		})
	}
}

func TestKDFDefaults(t *testing.T) {
	for _, f := range []func() ([]byte, error){
		func() ([]byte, error) { return c.PBKDF2([]byte("password"), []byte("somesalt"), nil) },
		func() ([]byte, error) { return c.HKDF([]byte("key"), nil, nil, nil) },
		func() ([]byte, error) { return c.Scrypt([]byte("password"), []byte("somesalt"), nil) },
		func() ([]byte, error) { return c.Argon2id([]byte("password"), []byte("somesalt"), nil) },
	} {
		if out, err := f(); err != nil || len(out) != 32 {
			t.Fatalf("default = %x, %v", out, err)
		}
	}
}

func TestKDFRejectsInvalidParameters(t *testing.T) {
	maximum := int(^uint(0) >> 1)
	for _, o := range []c.PBKDF2Options{
		{Hash: "sha256", Iterations: 0, KeyLength: 32}, {Hash: "sha256", Iterations: -1, KeyLength: 32},
		{Hash: "sha256", Iterations: maximum, KeyLength: 32}, {Hash: "sha256", Iterations: 1, KeyLength: maximum},
		{Hash: "sha256", Iterations: 2000000, KeyLength: 1000}, {Hash: "sha256", Iterations: 1, KeyLength: 0},
	} {
		if out, err := c.PBKDF2(nil, nil, &o); out != nil || !errors.Is(err, c.ErrKDFParameters) {
			t.Fatalf("PBKDF2 accepted %+v: %v", o, err)
		}
	}
	for _, o := range []c.HKDFOptions{{Hash: "sha256", KeyLength: 0}, {Hash: "sha256", KeyLength: -1}, {Hash: "sha256", KeyLength: 8161}, {Hash: "sha256", KeyLength: maximum}} {
		if out, err := c.HKDF(nil, nil, nil, &o); out != nil || !errors.Is(err, c.ErrKDFParameters) {
			t.Fatalf("HKDF accepted %+v", o)
		}
	}
	for _, o := range []c.ScryptOptions{
		{N: 0, R: 1, P: 1, KeyLength: 32}, {N: 3, R: 1, P: 1, KeyLength: 32}, {N: 16, R: 0, P: 1, KeyLength: 32},
		{N: 16, R: 1, P: 0, KeyLength: 32}, {N: maximum, R: maximum, P: maximum, KeyLength: 32},
		{N: 1 << 20, R: 32, P: 1, KeyLength: 32}, {N: 1 << 17, R: 12, P: 16, KeyLength: 32},
		{N: 16, R: 1, P: 1, KeyLength: 0},
	} {
		if out, err := c.Scrypt(nil, nil, &o); out != nil || !errors.Is(err, c.ErrKDFParameters) {
			t.Fatalf("scrypt accepted %+v: %v", o, err)
		}
	}
	for _, o := range []c.Argon2idOptions{
		{Time: 0, Memory: 64, Threads: 1, KeyLength: 32}, {Time: 1, Memory: 0, Threads: 1, KeyLength: 32},
		{Time: 1, Memory: 64, Threads: 0, KeyLength: 32}, {Time: 1, Memory: 64, Threads: 9, KeyLength: 32},
		{Time: 1, Memory: 64, Threads: 1, KeyLength: 0}, {Time: maximum, Memory: maximum, Threads: maximum, KeyLength: maximum},
		{Time: 10, Memory: 256 * 1024, Threads: 1, KeyLength: 32},
	} {
		if out, err := c.Argon2id(nil, []byte("somesalt"), &o); out != nil || !errors.Is(err, c.ErrKDFParameters) {
			t.Fatalf("Argon2id accepted %+v", o)
		}
	}
	if _, err := c.Argon2id(nil, nil, nil); err == nil {
		t.Fatal("short salt accepted")
	}
	if _, err := c.PBKDF2(nil, nil, &c.PBKDF2Options{Hash: "unknown", Iterations: 1, KeyLength: 32}); !errors.Is(err, c.ErrUnsupportedHash) {
		t.Fatal("unknown PBKDF2 hash accepted")
	}
	if _, err := c.HKDF(nil, nil, nil, &c.HKDFOptions{Hash: "unknown", KeyLength: 32}); !errors.Is(err, c.ErrUnsupportedHash) {
		t.Fatal("unknown HKDF hash accepted")
	}
	large := make([]byte, c.MaxKDFInput+1)
	for _, f := range []func() ([]byte, error){
		func() ([]byte, error) { return c.PBKDF2(large, nil, nil) }, func() ([]byte, error) { return c.HKDF(nil, nil, large, nil) },
		func() ([]byte, error) { return c.Scrypt(nil, large, nil) }, func() ([]byte, error) { return c.Argon2id(large, []byte("somesalt"), nil) },
	} {
		if _, err := f(); !errors.Is(err, c.ErrKDFParameters) {
			t.Fatal("oversized input accepted")
		}
	}
}

func TestKDFStickyErrors(t *testing.T) {
	for _, fail := range []func(*c.CryptoData) *c.CryptoData{
		func(p *c.CryptoData) *c.CryptoData { return p.PBKDF2(nil, &c.PBKDF2Options{}) },
		func(p *c.CryptoData) *c.CryptoData { return p.HKDF(nil, nil, &c.HKDFOptions{}) },
		func(p *c.CryptoData) *c.CryptoData { return p.Scrypt(nil, &c.ScryptOptions{}) },
		func(p *c.CryptoData) *c.CryptoData { return p.Argon2id(nil, &c.Argon2idOptions{}) },
	} {
		p := fail(c.Init("secret"))
		first := p.Err()
		p.PBKDF2(nil, nil).HKDF(nil, nil, nil).Scrypt(nil, nil).Argon2id(nil, nil).Hex()
		if first == nil || p.Err() != first || p.Bytes() != nil {
			t.Fatal("KDF chain continued after error")
		}
		if p.Reset().String() != "secret" || p.Err() != nil {
			t.Fatal("KDF Reset failed")
		}
	}
}
