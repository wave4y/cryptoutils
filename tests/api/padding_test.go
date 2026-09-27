package cryptoutils_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/wave4y/cryptoutils"
)

func TestPKCS7PaddingRoundTrip(t *testing.T) {
	for _, blockSize := range []int{1, 8, 16, 255} {
		for _, size := range []int{0, 1, blockSize - 1, blockSize, blockSize + 1, 2 * blockSize} {
			t.Run(fmt.Sprintf("block=%d/length=%d", blockSize, size), func(t *testing.T) {
				input := bytes.Repeat([]byte{0xa5}, size)
				padded, err := cryptoutils.PKCS7Padding(input, blockSize)
				if err != nil {
					t.Fatal(err)
				}
				padLen := blockSize - size%blockSize
				if len(padded) != size+padLen || !bytes.Equal(padded[size:], bytes.Repeat([]byte{byte(padLen)}, padLen)) {
					t.Fatalf("incorrect padding: %x", padded)
				}
				got, err := cryptoutils.PKCS7UnPadding(padded, blockSize)
				if err != nil || !bytes.Equal(got, input) {
					t.Fatalf("unpadding = %x, %v; want %x", got, err, input)
				}
			})
		}
	}
}

func TestPKCS7RejectsInvalidBlockSizes(t *testing.T) {
	for _, size := range []int{-1, 0, 256, 1000} {
		if got, err := cryptoutils.PKCS7Padding(nil, size); err == nil || got != nil {
			t.Fatalf("padding block size %d returned %x, %v", size, got, err)
		}
		if got, err := cryptoutils.PKCS7UnPadding([]byte{1}, size); err == nil || got != nil {
			t.Fatalf("unpadding block size %d returned %x, %v", size, got, err)
		}
	}
}

func TestPKCS7RejectsMalformedPadding(t *testing.T) {
	for _, input := range [][]byte{
		nil,
		{},
		{1},
		{0, 0, 0, 0, 0, 0, 0, 0},
		{0, 0, 0, 0, 0, 0, 0, 9},
		{0, 0, 0, 0, 0, 0, 0, 255},
		{0, 0, 0, 0, 0, 0, 1, 2},
		{0, 0, 0, 0, 0, 0, 3, 3},
		{1, 8, 8, 8, 8, 8, 8, 8},
	} {
		if got, err := cryptoutils.PKCS7UnPadding(input, 8); err == nil || got != nil {
			t.Fatalf("invalid input %x returned %x, %v", input, got, err)
		}
	}
}

func TestPKCS7OwnsReturnedBytes(t *testing.T) {
	backing := bytes.Repeat([]byte{0x41}, 32)
	padded, err := cryptoutils.PKCS7Padding(backing[:3], 8)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(backing, bytes.Repeat([]byte{0x41}, 32)) {
		t.Fatal("padding mutated the input backing array")
	}
	got, err := cryptoutils.PKCS7UnPadding(padded, 8)
	if err != nil {
		t.Fatal(err)
	}
	got[0] = 'Z'
	if padded[0] != 'A' {
		t.Fatal("unpadding returned a slice of caller-owned data")
	}
	padded[0] = 'Y'
	if backing[0] != 'A' {
		t.Fatal("padding returned a slice of caller-owned data")
	}
}

func TestPKCS5Compatibility(t *testing.T) {
	padded := cryptoutils.PKCS5Padding([]byte("hello"), 8)
	got, err := cryptoutils.PKCS5UnPadding(padded)
	if err != nil || string(got) != "hello" {
		t.Fatalf("PKCS5 round trip = %q, %v", got, err)
	}
	for _, blockSize := range []int{-1, 0, 1, 16, 256} {
		if got := cryptoutils.PKCS5Padding([]byte("hello"), blockSize); got != nil {
			t.Fatalf("PKCS5 accepted block size %d", blockSize)
		}
	}
	for _, input := range [][]byte{nil, {0}, {1, 1, 1, 1, 1, 1, 1, 0}, bytes.Repeat([]byte{16}, 16)} {
		if got, err := cryptoutils.PKCS5UnPadding(input); err == nil || got != nil {
			t.Fatalf("PKCS5 accepted malformed padding %x", input)
		}
	}
}
