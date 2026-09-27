package sm4_test

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"testing"

	"www.gitlablow.com/wave4y/cryptoutils/sm4"
)

const (
	vectorKey   = "0123456789abcdeffedcba9876543210"
	vectorPlain = "0123456789abcdeffedcba9876543210"
	vectorCrypt = "681edf34d206965e86b3e94f536e4246"
)

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func newBlock(t *testing.T) cipher.Block {
	t.Helper()
	block, err := sm4.NewCipher(decodeHex(t, vectorKey))
	if err != nil {
		t.Fatal(err)
	}
	return block
}

func TestStandardVector(t *testing.T) {
	// GB/T 32907-2016 examples, reproduced in:
	// https://datatracker.ietf.org/doc/html/draft-ribose-cfrg-sm4-09#section-12
	block := newBlock(t)
	if block.BlockSize() != 16 {
		t.Fatalf("BlockSize = %d; want 16", block.BlockSize())
	}
	plain := decodeHex(t, vectorPlain)
	crypt := decodeHex(t, vectorCrypt)
	dst := make([]byte, sm4.BlockSize)
	block.Encrypt(dst, plain)
	if !bytes.Equal(dst, crypt) {
		t.Fatalf("Encrypt = %x; want %x", dst, crypt)
	}
	block.Decrypt(dst, crypt)
	if !bytes.Equal(dst, plain) {
		t.Fatalf("Decrypt = %x; want %x", dst, plain)
	}
	block.Encrypt(dst, dst)
	if !bytes.Equal(dst, crypt) {
		t.Fatalf("in-place Encrypt = %x; want %x", dst, crypt)
	}
	block.Decrypt(dst, dst)
	if !bytes.Equal(dst, plain) {
		t.Fatalf("in-place Decrypt = %x; want %x", dst, plain)
	}
}

func TestMillionIterationsVector(t *testing.T) {
	if testing.Short() {
		t.Skip("million-iteration standard vector")
	}
	block := newBlock(t)
	data := decodeHex(t, vectorPlain)
	for i := 0; i < 1000000; i++ {
		block.Encrypt(data, data)
	}
	const want = "595298c7c6fd271f0402f804c33d3f66"
	if hex.EncodeToString(data) != want {
		t.Fatalf("Encrypt repeated 1000000 times = %x; want %s", data, want)
	}
}

func TestKeyValidationAndOwnership(t *testing.T) {
	for _, length := range []int{0, 1, 15, 17, 24, 32} {
		block, err := sm4.NewCipher(make([]byte, length))
		if block != nil || err != sm4.KeySizeError(length) {
			t.Errorf("NewCipher with %d-byte key = %v, %v; want nil, KeySizeError", length, block, err)
		}
	}
	key := decodeHex(t, vectorKey)
	block, err := sm4.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	for i := range key {
		key[i] = 0
	}
	dst := make([]byte, sm4.BlockSize)
	block.Encrypt(dst, decodeHex(t, vectorPlain))
	if hex.EncodeToString(dst) != vectorCrypt {
		t.Fatal("cipher retained mutable caller key")
	}
}

func TestOnlyFirstBlockIsProcessed(t *testing.T) {
	block := newBlock(t)
	for _, tt := range []struct {
		name, input, want string
		crypt             func([]byte, []byte)
	}{
		{"encrypt", vectorPlain, vectorCrypt, block.Encrypt},
		{"decrypt", vectorCrypt, vectorPlain, block.Decrypt},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tail := bytes.Repeat([]byte{0xa5}, sm4.BlockSize)
			src := append(decodeHex(t, tt.input), tail...)
			original := append([]byte(nil), src...)
			dst := bytes.Repeat([]byte{0xa5}, 2*sm4.BlockSize)
			tt.crypt(dst, src)
			if !bytes.Equal(dst[:sm4.BlockSize], decodeHex(t, tt.want)) || !bytes.Equal(dst[sm4.BlockSize:], tail) {
				t.Fatalf("unexpected output or overwritten tail: %x", dst)
			}
			if !bytes.Equal(src, original) {
				t.Fatal("source changed")
			}
			// These full slices overlap, but their first blocks are adjacent.
			shared := append(original, tail...)
			tt.crypt(shared[sm4.BlockSize:], shared)
			if !bytes.Equal(shared[sm4.BlockSize:2*sm4.BlockSize], decodeHex(t, tt.want)) {
				t.Fatal("adjacent blocks did not work")
			}
		})
	}
}

func mustPanic(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	f()
}

func TestInvalidBuffersPanicBeforeWriting(t *testing.T) {
	block := newBlock(t)
	for name, crypt := range map[string]func([]byte, []byte){
		"encrypt": block.Encrypt,
		"decrypt": block.Decrypt,
	} {
		t.Run(name, func(t *testing.T) {
			for _, length := range []int{0, 1, 15} {
				t.Run(fmt.Sprintf("short=%d", length), func(t *testing.T) {
					dst := bytes.Repeat([]byte{0xa5}, sm4.BlockSize)
					before := append([]byte(nil), dst...)
					mustPanic(t, func() { crypt(dst, make([]byte, length)) })
					mustPanic(t, func() { crypt(dst[:length], make([]byte, sm4.BlockSize)) })
					if !bytes.Equal(dst, before) {
						t.Fatal("invalid buffer operation partially changed output")
					}
				})
			}
			for offset := 1; offset < sm4.BlockSize; offset++ {
				data := bytes.Repeat([]byte{0xa5}, 2*sm4.BlockSize)
				before := append([]byte(nil), data...)
				mustPanic(t, func() { crypt(data[offset:], data) })
				mustPanic(t, func() { crypt(data, data[offset:]) })
				if !bytes.Equal(data, before) {
					t.Fatalf("offset=%d: rejected overlap changed output", offset)
				}
			}
		})
	}
}
