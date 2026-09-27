package cryptoutils_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	c "www.gitlablow.com/wave4y/cryptoutils"
	"www.gitlablow.com/wave4y/cryptoutils/utils"
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

func TestHashVectors(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		method     func(*c.CryptoData) *c.CryptoData
	}{
		{"md4", "a448017aaf21d8525fc10ae87aa6729d", (*c.CryptoData).Md4},
		{"md5", "900150983cd24fb0d6963f7d28e17f72", (*c.CryptoData).Md5},
		{"sha1", "a9993e364706816aba3e25717850c26c9cd0d89d", (*c.CryptoData).Sha1},
		{"sha256", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", (*c.CryptoData).Sha256},
		{"sha512", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", (*c.CryptoData).Sha512},
		{"sm3", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", (*c.CryptoData).Sm3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := c.Init("abc").Hash(tc.name).String(); got != tc.want {
				t.Fatalf("Hash = %q", got)
			}
			if got := tc.method(c.Init("abc")).String(); got != tc.want {
				t.Fatalf("method = %q", got)
			}
			if got := c.Init("abc").HashBytes(tc.name).Hex().String(); got != tc.want {
				t.Fatalf("HashBytes = %q", got)
			}
		})
	}
	digest := sha256.Sum256([]byte("abc"))
	if got := c.Init("abc").HashBytes(" SHA-256 ").Base64Encode().String(); got != base64.StdEncoding.EncodeToString(digest[:]) {
		t.Fatalf("raw digest encoding = %q", got)
	}
}

func TestEncodingRoundTrips(t *testing.T) {
	for _, src := range [][]byte{nil, {}, []byte("中文🙂"), {0, 1, 127, 128, 255}} {
		if out, err := c.Init(src).Hex().HexDecode().Result(); err != nil || !bytes.Equal(out, src) {
			t.Fatalf("hex = %x, %v", out, err)
		}
		if out, err := c.Init(src).Base64Encode().Base64Decode().Result(); err != nil || !bytes.Equal(out, src) {
			t.Fatalf("base64 = %x, %v", out, err)
		}
	}
}

func TestHMACSHA256Vector(t *testing.T) {
	// RFC 4231, test case 1.
	key := bytes.Repeat([]byte{0x0b}, 20)
	data := []byte("Hi There")
	const want = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
	tag := c.HMACSHA256(data, key)
	if hex.EncodeToString(tag) != want || c.Init(data).HMACSHA256(key).String() != want {
		t.Fatalf("HMAC = %x", tag)
	}
	if !c.VerifyHMACSHA256(data, key, tag) {
		t.Fatal("valid tag rejected")
	}
	for _, invalid := range [][]byte{nil, tag[:31], append(append([]byte{}, tag...), 0), bytes.Repeat([]byte{0}, 32)} {
		if c.VerifyHMACSHA256(data, key, invalid) {
			t.Fatal("invalid tag accepted")
		}
	}
	if c.VerifyHMACSHA256([]byte("altered"), key, tag) || c.VerifyHMACSHA256(data, []byte("wrong"), tag) {
		t.Fatal("wrong key or message accepted")
	}
}

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

func ExampleCryptoData_Reset() {
	p := c.Init("abc")
	fmt.Println(p.Hex().String())
	fmt.Println(p.Reset().Base64Encode().String())
	// Output:
	// 616263
	// YWJj
}

func ExampleEncryptAESGCM() {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	aad := []byte("example:v1")
	encrypted, err := c.EncryptAESGCM([]byte("hello"), key, aad)
	if err != nil {
		panic(err)
	}
	plaintext, err := c.DecryptAESGCM(encrypted, key, aad)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(plaintext))
	// Output: hello
}
