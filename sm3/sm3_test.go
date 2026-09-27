package sm3_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/wave4y/cryptoutils/sm3"
)

func TestStandardVectors(t *testing.T) {
	// GB/T 32905-2016 examples, reproduced in:
	// https://datatracker.ietf.org/doc/html/draft-sca-cfrg-sm3-01#appendix-A
	tests := []struct {
		name, input, want string
	}{
		{"abc", "abc", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"},
		{"abcd repeated", strings.Repeat("abcd", 16), "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sm3.Sum([]byte(tt.input))
			if hex.EncodeToString(got[:]) != tt.want {
				t.Fatalf("Sum = %x; want %s", got, tt.want)
			}
		})
	}
}

func TestPaddingBoundariesAndStreaming(t *testing.T) {
	// Independent expected values from OpenSSL SM3 (Python hashlib.new("sm3")),
	// using bytes(i % 251 for i in range(length)). These exercise both padding
	// branches and the transitions between one and multiple message blocks.
	tests := []struct {
		length int
		want   string
	}{
		{0, "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"},
		{1, "2daef60e7a0b8f5e024c81cd2ab3109f2b4f155cf83adeb2ae5532f74a157fdf"},
		{55, "a79cf9dcee3404abf7f769698201647fd9d3ff61d629d0f58bb4b5579a427db8"},
		{56, "62f7363b15f4de76dd925c493b9d6d00d4ba0ef2a1f334c1d0f13b293aeb40d1"},
		{63, "6165e4cbb15cde01c6226e0015a47f710f8f8e1f2c296700033bb34d9212109c"},
		{64, "93566f236d157aae078d1ddb5cebdbba1520b5142e22a8915564345ba2ae1d63"},
		{65, "c886e6814be748285a10b28ae62ddacd85db830cd2cf3a2bfa2f729c15f63618"},
		{119, "8f3ea392a89a7119982d6634660db1a95f35d68267a2235e3255998a857f4fbf"},
		{120, "6babee35e6a1515af9d6255109c24f3c08897829422c6225d235fd4c8527e9ec"},
		{127, "bca3436d828517a6a6893a9e309e06e7b7b29c6e3f78b4814b23efe149962980"},
		{128, "a9e7985473ca09df1510d83b572f72375430756c4a661b00724afeb8b75dd0a5"},
		{129, "2783a0e9b3767a694f90027806e392ae959d919baed7ceca40c7c8077711cb7b"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("length=%d", tt.length), func(t *testing.T) {
			data := make([]byte, tt.length)
			for i := range data {
				data[i] = byte(i % 251)
			}
			digest := sm3.Sum(data)
			if hex.EncodeToString(digest[:]) != tt.want {
				t.Fatalf("Sum = %x; want %s", digest, tt.want)
			}
			for _, step := range []int{1, 7, 63, 64, 65, 128} {
				h := sm3.New()
				if h.Size() != 32 || h.BlockSize() != 64 {
					t.Fatalf("unexpected hash dimensions: Size=%d BlockSize=%d", h.Size(), h.BlockSize())
				}
				if n, err := h.Write(nil); n != 0 || err != nil {
					t.Fatalf("Write(nil) = %d, %v", n, err)
				}
				for start := 0; start < len(data); start += step {
					end := start + step
					if end > len(data) {
						end = len(data)
					}
					if n, err := h.Write(data[start:end]); n != end-start || err != nil {
						t.Fatalf("Write = %d, %v; want %d, nil", n, err, end-start)
					}
					// Summing a partial message must not affect subsequent writes.
					partial := h.Sum(nil)
					if !bytes.Equal(partial, h.Sum(nil)) {
						t.Fatal("repeated Sum changed digest")
					}
				}
				got := h.Sum(nil)
				if hex.EncodeToString(got) != tt.want {
					t.Errorf("step=%d: Sum = %x; want %s", step, got, tt.want)
				}
				prefix := []byte("prefix")
				if prefixed := h.Sum(prefix); !bytes.Equal(prefixed, append([]byte("prefix"), digest[:]...)) {
					t.Errorf("step=%d: Sum(prefix) = %x", step, prefixed)
				}
				got[0] ^= 0xff
				if !bytes.Equal(h.Sum(nil), digest[:]) {
					t.Fatal("modifying Sum result affected hash state")
				}
				h.Reset()
				if hex.EncodeToString(h.Sum(nil)) != tests[0].want {
					t.Fatal("Reset did not restore empty hash")
				}
				h.Write(data)
				if !bytes.Equal(h.Sum(nil), digest[:]) {
					t.Fatal("hash after Reset differs")
				}
			}
		})
	}
}
