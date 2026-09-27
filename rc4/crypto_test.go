package utils

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestRC4KnownVectors(t *testing.T) {
	tests := []struct {
		name, key, plain, ciphertext string
	}{
		{"Key", "Key", "Plaintext", "bbf316e8d940af0ad3"},
		{"Wiki", "Wiki", "pedia", "1021bf0420"},
		{"RFC6229", "\x01\x02\x03\x04\x05", strings.Repeat("\x00", 16), "b2396305f03dc027ccc3524a0a1118a8"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := RC4Encrypt(test.plain, []byte(test.key))
			if err != nil || got != test.ciphertext {
				t.Fatalf("encrypt = %q, %v; want %q", got, err, test.ciphertext)
			}
			plain, err := RC4Decrypt(test.ciphertext, []byte(test.key))
			if err != nil || plain != test.plain {
				t.Fatalf("decrypt = %q, %v; want %q", plain, err, test.plain)
			}
			if got := Rc4Encrypt(test.plain, []byte(test.key)); got != test.ciphertext {
				t.Fatalf("compatibility encrypt = %q", got)
			}
			if got := Rc4Decrypt(test.ciphertext, []byte(test.key)); got != test.plain {
				t.Fatalf("compatibility decrypt = %q", got)
			}
		})
	}
}

func TestRC4InvalidInputs(t *testing.T) {
	for _, key := range [][]byte{nil, make([]byte, 257)} {
		if got, err := RC4Encrypt("plain", key); err == nil || got != "" {
			t.Errorf("encrypt with key length %d = %q, %v", len(key), got, err)
		}
		if got, err := RC4Decrypt("00", key); err == nil || got != "" {
			t.Errorf("decrypt with key length %d = %q, %v", len(key), got, err)
		}
		if got := Rc4Encrypt("plain", key); got != "" {
			t.Errorf("compatibility encrypt returned %q for invalid key", got)
		}
		if got := Rc4Decrypt("00", key); got != "" {
			t.Errorf("compatibility decrypt returned %q for invalid key", got)
		}
	}
	for _, invalid := range []string{"0", "61f", "6162zz", "xx"} {
		if got, err := RC4Decrypt(invalid, []byte("Key")); err == nil || got != "" {
			t.Errorf("decrypt %q = %q, %v", invalid, got, err)
		}
		if got := Rc4Decrypt(invalid, []byte("Key")); got != "" {
			t.Errorf("compatibility decrypt %q returned %q", invalid, got)
		}
		if got, err := HexDecodeE(invalid); err == nil || got != "" {
			t.Errorf("hex decode %q = %q, %v", invalid, got, err)
		}
		if got := HexDecode(invalid); got != "" {
			t.Errorf("compatibility hex decode %q returned %q", invalid, got)
		}
	}
}

func TestRC4RoundTrip(t *testing.T) {
	for _, plain := range []string{"", "\x00\xff中文\x01"} {
		encoded, err := RC4Encrypt(plain, []byte("legacy key"))
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := RC4Decrypt(encoded, []byte("legacy key"))
		if err != nil || decoded != plain {
			t.Fatalf("round trip = %q, %v; want %q", decoded, err, plain)
		}
	}
}

func TestRandomString(t *testing.T) {
	for _, length := range []int{0, 1, 31, 128, 256} {
		got, err := RandomStringE(length)
		if err != nil || len(got) != length {
			t.Fatalf("length %d: got %d characters, error %v", length, len(got), err)
		}
		for _, character := range got {
			if !strings.ContainsRune(randomAlphabet, character) {
				t.Fatalf("unexpected random character %q", character)
			}
		}
	}
	if got, err := RandomStringE(-1); err == nil || got != "" {
		t.Fatalf("negative length = %q, %v", got, err)
	}
	if got := RandomString(-1); got != "" {
		t.Fatalf("compatibility negative length = %q", got)
	}
	if got := RandomString(16); len(got) != 16 {
		t.Fatalf("compatibility length = %d", len(got))
	}
}

func TestRandomStringRejectionSampling(t *testing.T) {
	source := bytes.NewReader([]byte{248, 249, 250, 251, 252, 253, 254, 255, 0, 61, 62, 247})
	got, err := randomStringFromReader(4, source)
	if err != nil || got != "a9a9" {
		t.Fatalf("rejection sampling = %q, %v; want a9a9", got, err)
	}
}

type failingReader struct {
	err error
}

func (r failingReader) Read([]byte) (int, error) {
	return 0, r.err
}

func TestRandomStringSourceErrors(t *testing.T) {
	wantErr := errors.New("random source unavailable")
	if got, err := randomStringFromReader(1, failingReader{wantErr}); !errors.Is(err, wantErr) || got != "" {
		t.Fatalf("source failure = %q, %v", got, err)
	}
	if got, err := randomStringFromReader(3, bytes.NewReader([]byte{0, 1})); !errors.Is(err, io.ErrUnexpectedEOF) || got != "" {
		t.Fatalf("short source = %q, %v", got, err)
	}
	// Even after producing a valid prefix, a later failure must return no output.
	if got, err := randomStringFromReader(129, bytes.NewReader(make([]byte, 128))); !errors.Is(err, io.EOF) || got != "" {
		t.Fatalf("partial generation = %q, %v", got, err)
	}
	if got, err := randomStringFromReader(0, nil); err != nil || got != "" {
		t.Fatalf("zero length = %q, %v", got, err)
	}
}

func TestEncodings(t *testing.T) {
	plain := "中文 &?=+/%\x00"
	encoded := UrlEncode(plain)
	if got := UrlDncode(plain); got != encoded {
		t.Fatalf("URL compatibility alias = %q; want %q", got, encoded)
	}
	if got, err := UrlDecode(encoded); err != nil || got != plain {
		t.Fatalf("URL round trip = %q, %v", got, err)
	}
	if got, err := UrlDecode("%xx"); err == nil || got != "" {
		t.Fatalf("invalid URL = %q, %v", got, err)
	}
	if got, err := HexDecodeE(HexEncode(plain)); err != nil || got != plain {
		t.Fatalf("hex round trip = %q, %v", got, err)
	}
	if got := HexDecode(HexEncode(plain)); got != plain {
		t.Fatalf("compatibility hex round trip = %q", got)
	}
	if got, err := Base64Decode(Base64Encode(plain)); err != nil || got != plain {
		t.Fatalf("base64 round trip = %q, %v", got, err)
	}
	if got, err := Base64Decode("YWJj!"); err == nil || got != "" {
		t.Fatalf("invalid base64 = %q, %v", got, err)
	}
	if got := Md5Encode("abc"); got != "900150983cd24fb0d6963f7d28e17f72" {
		t.Fatalf("MD5 = %q", got)
	}
}
