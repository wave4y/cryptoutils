package cryptoutils_test

import (
	"bytes"
	"fmt"
	c "github.com/wave4y/cryptoutils"
	"testing"
)

func TestAESGCMRoundTrip(t *testing.T) {
	for _, keySize := range []int{16, 24, 32} {
		for _, size := range []int{0, 1, 16, 33} {
			t.Run(fmt.Sprintf("key=%d/plaintext=%d", keySize, size), func(t *testing.T) {
				key := bytes.Repeat([]byte{0x71}, keySize)
				plaintext := bytes.Repeat([]byte{0xa5}, size)
				aad := []byte("record:42")
				envelope, err := c.EncryptAESGCM(plaintext, key, aad)
				if err != nil {
					t.Fatal(err)
				}
				if len(envelope) != 12+size+16 {
					t.Fatalf("unexpected envelope length %d", len(envelope))
				}
				got, err := c.DecryptAESGCM(envelope, key, aad)
				if err != nil || !bytes.Equal(got, plaintext) {
					t.Fatalf("decrypt = %x, %v; want %x", got, err, plaintext)
				}
				second, err := c.EncryptAESGCM(plaintext, key, aad)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Equal(envelope[:12], second[:12]) {
					t.Fatal("encryption reused the nonce")
				}
			})
		}
	}
}

func TestAESGCMKnownVectors(t *testing.T) {
	// Fixed vectors from Go's crypto/cipher GCM tests verify the wire format
	// independently of this package's encryption function.
	vectors := []struct{ key, tag string }{
		{"11754cd72aec309bf52f7687212e8957", "250327c674aaf477aef2675748cf6971"},
		{"e2e001a36c60d2bf40d69ff5b2b1161ea218db263be16a4e", "c7b8da1fe2e3dccc4071ba92a0a57ba8"},
		{"5394e890d37ba55ec9d5f327f15680f6a63ef5279c79331643ad0af6d2623525", "d9b260d4bc4630733ffb642f5ce45726"},
	}
	for _, vector := range vectors {
		key := cryptoTestHex(t, vector.key)
		envelope := cryptoTestHex(t, "3c819d9a9bed087615030b65"+vector.tag)
		got, err := c.DecryptAESGCM(envelope, key, nil)
		if err != nil || len(got) != 0 {
			t.Fatalf("key length %d: got %x, %v; want empty plaintext", len(key), got, err)
		}
	}
}

func TestAESGCMRejectsUnauthenticatedData(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	aad := []byte("record:42")
	envelope, err := c.EncryptAESGCM([]byte("confidential record"), key, aad)
	if err != nil {
		t.Fatal(err)
	}
	for i := range envelope {
		changed := append([]byte(nil), envelope...)
		changed[i] ^= 1
		if got, err := c.DecryptAESGCM(changed, key, aad); err == nil || got != nil {
			t.Fatalf("tampered byte %d returned %x, %v", i, got, err)
		}
	}
	for n := 0; n < len(envelope); n++ {
		if got, err := c.DecryptAESGCM(envelope[:n], key, aad); err == nil || got != nil {
			t.Fatalf("truncated length %d returned %x, %v", n, got, err)
		}
	}
	wrongKey := bytes.Repeat([]byte{2}, 32)
	if got, err := c.DecryptAESGCM(envelope, wrongKey, aad); err == nil || got != nil {
		t.Fatalf("wrong key returned %x, %v", got, err)
	}
	for _, wrongAAD := range [][]byte{nil, []byte("record:43")} {
		if got, err := c.DecryptAESGCM(envelope, key, wrongAAD); err == nil || got != nil {
			t.Fatalf("wrong AAD returned %x, %v", got, err)
		}
	}
}

func TestAESGCMRejectsInvalidKeys(t *testing.T) {
	for _, size := range []int{0, 8, 15, 17, 23, 25, 31, 33} {
		key := make([]byte, size)
		if got, err := c.EncryptAESGCM(nil, key, nil); err == nil || got != nil {
			t.Fatalf("encrypt with %d byte key returned %x, %v", size, got, err)
		}
		if got, err := c.DecryptAESGCM(make([]byte, 28), key, nil); err == nil || got != nil {
			t.Fatalf("decrypt with %d byte key returned %x, %v", size, got, err)
		}
	}
}

func TestAESGCMDoesNotMutateInputs(t *testing.T) {
	backing := bytes.Repeat([]byte{0x77}, 64)
	plaintext := backing[:3]
	key := bytes.Repeat([]byte{1}, 16)
	aad := []byte("metadata")
	envelope, err := c.EncryptAESGCM(plaintext, key, aad)
	if err != nil {
		t.Fatal(err)
	}
	originalEnvelope := append([]byte(nil), envelope...)
	decrypted, err := c.DecryptAESGCM(envelope, key, aad)
	if err != nil {
		t.Fatal(err)
	}
	decrypted[0] ^= 1
	if !bytes.Equal(backing, bytes.Repeat([]byte{0x77}, 64)) || !bytes.Equal(key, bytes.Repeat([]byte{1}, 16)) || string(aad) != "metadata" || !bytes.Equal(envelope, originalEnvelope) {
		t.Fatal("encryption or decryption mutated a caller-owned input")
	}
}

func TestAESGCMChainRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x52}, 24)
	enc := c.Init("hello world")
	enc.SetKey(key)
	envelope, err := enc.AESGCMEncrypt([]byte("context")).Result()
	if err != nil {
		t.Fatal(err)
	}
	dec := c.Init(envelope)
	dec.SetKey(key)
	got, err := dec.AESGCMDecrypt([]byte("context")).Result()
	if err != nil || string(got) != "hello world" || dec.String() != "hello world" {
		t.Fatalf("chain decrypt = %q, %v", got, err)
	}
}
