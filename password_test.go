package cryptoutils_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
	c "www.gitlablow.com/wave4y/cryptoutils"
)

func TestBcryptKnownVector(t *testing.T) {
	// Fixed upstream x/crypto bcrypt interoperability vector.
	const encoded = "$2a$10$XajjQvNhvvRt5GSeFk1xFeyqRrsxkhBkUiQeg0dt.wU1qD4aFDcga"
	for _, version := range []string{"2a", "2b", "2y"} {
		if err := c.VerifyBcrypt([]byte("allmine"), "$"+version+encoded[3:]); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.VerifyBcrypt([]byte("wrong"), encoded); !errors.Is(err, c.ErrPasswordMismatch) {
		t.Fatalf("wrong password: %v", err)
	}
	if p := c.Init("allmine").VerifyBcrypt(encoded); p.Err() != nil || p.String() != "allmine" {
		t.Fatal("successful verify changed input")
	}
}

func TestBcryptGenerationAndBounds(t *testing.T) {
	password := []byte("password")
	first, err := c.HashBcrypt(password, 4)
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.HashBcrypt(password, 4)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("bcrypt reused salt")
	}
	if err := c.VerifyBcrypt(password, first); err != nil {
		t.Fatal(err)
	}
	if p := c.Init(password).HashBcrypt(4); p.Err() != nil || c.VerifyBcrypt(password, p.String()) != nil {
		t.Fatal("bcrypt chain generation failed")
	}
	defaultHash, err := c.HashBcrypt(password, 0)
	if err != nil {
		t.Fatal(err)
	}
	if cost, err := bcrypt.Cost([]byte(defaultHash)); err != nil || cost != c.DefaultBcryptCost {
		t.Fatal("wrong default bcrypt cost")
	}
	for _, cost := range []int{-1, 1, 3, c.MaxBcryptCost + 1, int(^uint(0) >> 1)} {
		if out, err := c.HashBcrypt(password, cost); out != "" || err == nil {
			t.Fatal("invalid bcrypt cost accepted")
		}
	}
	long := bytes.Repeat([]byte("a"), 73)
	if _, err := c.HashBcrypt(long, 4); err == nil {
		t.Fatal("long bcrypt password accepted")
	}
	if err := c.VerifyBcrypt(long, first); err == nil {
		t.Fatal("long bcrypt password verified")
	}
	for _, encoded := range []string{"", first[:59], first + "x", "$3a$" + first[4:], "$2a$31$" + first[7:], "$2a$+4$" + first[7:], first[:59] + "!"} {
		if err := c.VerifyBcrypt(password, encoded); !errors.Is(err, c.ErrInvalidPasswordHash) {
			t.Fatalf("malformed bcrypt hash: %q: %v", encoded, err)
		}
	}
}

func TestArgon2idPasswordKnownVector(t *testing.T) {
	tag, err := hex.DecodeString("655ad15eac652dc59f7170a7332bf49b8469be1fdb9c28bb")
	if err != nil {
		t.Fatal(err)
	}
	encoded := "$argon2id$v=19$m=64,t=1,p=1$" + base64.RawStdEncoding.EncodeToString([]byte("somesalt")) + "$" + base64.RawStdEncoding.EncodeToString(tag)
	if err := c.VerifyArgon2id([]byte("password"), encoded); err != nil {
		t.Fatal(err)
	}
	if err := c.VerifyArgon2id([]byte("wrong"), encoded); !errors.Is(err, c.ErrPasswordMismatch) {
		t.Fatalf("wrong password: %v", err)
	}
	if p := c.Init("password").VerifyArgon2id(encoded); p.Err() != nil || p.String() != "password" {
		t.Fatal("successful Argon2id verify changed input")
	}
	invalid := []string{"", strings.Repeat("x", 513), encoded + "$extra", strings.Replace(encoded, "v=19", "v=16", 1), strings.Replace(encoded, "m=64", "m=4294967296", 1), strings.Replace(encoded, "t=1", "t=999999999999999999999", 1), strings.Replace(encoded, "p=1", "p=257", 1), strings.Replace(encoded, "p=1", "p=0", 1), strings.Replace(encoded, "m=64", "m=064", 1), strings.Replace(encoded, "m=64", "m=-1", 1), strings.Replace(encoded, "m=64,t=1,p=1", "m=262144,t=10,p=1", 1), strings.Replace(encoded, "m=64,t=1,p=1", "m=64,t=1,m=1", 1), encoded[:len(encoded)-1] + "!"}
	for _, bad := range invalid {
		if err := c.VerifyArgon2id([]byte("password"), bad); !errors.Is(err, c.ErrInvalidPasswordHash) {
			t.Fatalf("malformed Argon2id hash %q: %v", bad, err)
		}
	}
}

func TestArgon2idPasswordGeneration(t *testing.T) {
	opts := c.Argon2idOptions{Time: 1, Memory: 64, Threads: 1, KeyLength: 24}
	password := []byte("password")
	first, err := c.HashArgon2id(password, &opts)
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.HashArgon2id(password, &opts)
	if err != nil {
		t.Fatal(err)
	}
	if first == second || !strings.HasPrefix(first, "$argon2id$v=19$m=64,t=1,p=1$") {
		t.Fatal("PHC format or salt generation failed")
	}
	if err := c.VerifyArgon2id(password, first); err != nil {
		t.Fatal(err)
	}
	if p := c.Init(password).HashArgon2id(&opts); p.Err() != nil || c.VerifyArgon2id(password, p.String()) != nil {
		t.Fatal("Argon2id chain generation failed")
	}
	if defaults, err := c.HashArgon2id(password, nil); err != nil || !strings.HasPrefix(defaults, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Fatalf("default Argon2id hash: %v", err)
	}
	for _, length := range []int{0, 4, 15, 65, 1025} {
		bad := opts
		bad.KeyLength = length
		if _, err := c.HashArgon2id(password, &bad); err == nil {
			t.Fatal("invalid password tag size accepted")
		}
	}
	bad := opts
	bad.Time = 0
	if _, err := c.HashArgon2id(password, &bad); err == nil {
		t.Fatal("invalid Argon2id options accepted")
	}
	if _, err := c.HashArgon2id(make([]byte, c.MaxKDFInput+1), &opts); err == nil {
		t.Fatal("oversized password accepted")
	}
}

func TestPasswordStickyErrors(t *testing.T) {
	for _, fail := range []func(*c.CryptoData) *c.CryptoData{
		func(p *c.CryptoData) *c.CryptoData { return p.HashBcrypt(-1) },
		func(p *c.CryptoData) *c.CryptoData { return p.HashArgon2id(&c.Argon2idOptions{}) },
		func(p *c.CryptoData) *c.CryptoData { return p.VerifyBcrypt("invalid") },
		func(p *c.CryptoData) *c.CryptoData { return p.VerifyArgon2id("invalid") },
	} {
		p := fail(c.Init("password"))
		first := p.Err()
		p.HashBcrypt(4).HashArgon2id(nil).VerifyBcrypt("").VerifyArgon2id("").Hex()
		if first == nil || p.Err() != first || p.Bytes() != nil {
			t.Fatal("password failure not sticky")
		}
	}
}
