package cryptoutils_test

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"encoding/hex"
	"fmt"
	"testing"

	"www.gitlablow.com/wave4y/cryptoutils"
)

func TestAESGCMRoundTrip(t *testing.T) {
	for _, keySize := range []int{16, 24, 32} {
		for _, size := range []int{0, 1, 16, 33} {
			t.Run(fmt.Sprintf("key=%d/plaintext=%d", keySize, size), func(t *testing.T) {
				key := bytes.Repeat([]byte{0x71}, keySize)
				plaintext := bytes.Repeat([]byte{0xa5}, size)
				aad := []byte("record:42")
				envelope, err := cryptoutils.EncryptAESGCM(plaintext, key, aad)
				if err != nil {
					t.Fatal(err)
				}
				if len(envelope) != 12+size+16 {
					t.Fatalf("unexpected envelope length %d", len(envelope))
				}
				got, err := cryptoutils.DecryptAESGCM(envelope, key, aad)
				if err != nil || !bytes.Equal(got, plaintext) {
					t.Fatalf("decrypt = %x, %v; want %x", got, err, plaintext)
				}
				second, err := cryptoutils.EncryptAESGCM(plaintext, key, aad)
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
		got, err := cryptoutils.DecryptAESGCM(envelope, key, nil)
		if err != nil || len(got) != 0 {
			t.Fatalf("key length %d: got %x, %v; want empty plaintext", len(key), got, err)
		}
	}
}

func TestAESGCMRejectsUnauthenticatedData(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	aad := []byte("record:42")
	envelope, err := cryptoutils.EncryptAESGCM([]byte("confidential record"), key, aad)
	if err != nil {
		t.Fatal(err)
	}
	for i := range envelope {
		changed := append([]byte(nil), envelope...)
		changed[i] ^= 1
		if got, err := cryptoutils.DecryptAESGCM(changed, key, aad); err == nil || got != nil {
			t.Fatalf("tampered byte %d returned %x, %v", i, got, err)
		}
	}
	for n := 0; n < len(envelope); n++ {
		if got, err := cryptoutils.DecryptAESGCM(envelope[:n], key, aad); err == nil || got != nil {
			t.Fatalf("truncated length %d returned %x, %v", n, got, err)
		}
	}
	wrongKey := bytes.Repeat([]byte{2}, 32)
	if got, err := cryptoutils.DecryptAESGCM(envelope, wrongKey, aad); err == nil || got != nil {
		t.Fatalf("wrong key returned %x, %v", got, err)
	}
	for _, wrongAAD := range [][]byte{nil, []byte("record:43")} {
		if got, err := cryptoutils.DecryptAESGCM(envelope, key, wrongAAD); err == nil || got != nil {
			t.Fatalf("wrong AAD returned %x, %v", got, err)
		}
	}
}

func TestAESGCMRejectsInvalidKeys(t *testing.T) {
	for _, size := range []int{0, 8, 15, 17, 23, 25, 31, 33} {
		key := make([]byte, size)
		if got, err := cryptoutils.EncryptAESGCM(nil, key, nil); err == nil || got != nil {
			t.Fatalf("encrypt with %d byte key returned %x, %v", size, got, err)
		}
		if got, err := cryptoutils.DecryptAESGCM(make([]byte, 28), key, nil); err == nil || got != nil {
			t.Fatalf("decrypt with %d byte key returned %x, %v", size, got, err)
		}
	}
}

func TestAESGCMDoesNotMutateInputs(t *testing.T) {
	backing := bytes.Repeat([]byte{0x77}, 64)
	plaintext := backing[:3]
	key := bytes.Repeat([]byte{1}, 16)
	aad := []byte("metadata")
	envelope, err := cryptoutils.EncryptAESGCM(plaintext, key, aad)
	if err != nil {
		t.Fatal(err)
	}
	originalEnvelope := append([]byte(nil), envelope...)
	decrypted, err := cryptoutils.DecryptAESGCM(envelope, key, aad)
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
	enc := cryptoutils.Init("hello world")
	enc.SetKey(key)
	envelope, err := enc.AESGCMEncrypt([]byte("context")).Result()
	if err != nil {
		t.Fatal(err)
	}
	dec := cryptoutils.Init(envelope)
	dec.SetKey(key)
	got, err := dec.AESGCMDecrypt([]byte("context")).Result()
	if err != nil || string(got) != "hello world" || dec.String() != "hello world" {
		t.Fatalf("chain decrypt = %q, %v", got, err)
	}
}

func TestDESCBCEnvelopeRoundTrip(t *testing.T) {
	key := []byte("12345678")
	for _, plaintext := range []string{"", "a", "12345678", "hello world"} {
		t.Run(fmt.Sprintf("length=%d", len(plaintext)), func(t *testing.T) {
			enc := cryptoutils.Init(plaintext)
			enc.SetKey(key)
			envelope, err := enc.DesCBCEncrypt().Result()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.HasPrefix(envelope, []byte("CU-DES\x01")) {
				t.Fatalf("missing version prefix: %x", envelope)
			}
			dec := cryptoutils.Init(envelope)
			dec.SetKey(key)
			got, err := dec.DesDecrypt().Result()
			if err != nil || string(got) != plaintext || dec.String() != plaintext {
				t.Fatalf("decrypt = %q, %v; want %q", got, err, plaintext)
			}
			second := cryptoutils.Init(plaintext)
			second.SetKey(key)
			other, err := second.DesCBCEncrypt().Result()
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(envelope[7:15], other[7:15]) {
				t.Fatal("encryption reused the IV")
			}
		})
	}
}

func TestDESRejectsUnauthenticatedEnvelopes(t *testing.T) {
	key := []byte("12345678")
	enc := cryptoutils.Init("secret payload")
	enc.SetKey(key)
	envelope, err := enc.DesCBCEncrypt().Result()
	if err != nil {
		t.Fatal(err)
	}
	assertRejected := func(input, key []byte) {
		t.Helper()
		dec := cryptoutils.Init(input)
		dec.SetKey(key)
		got, err := dec.DesDecrypt().Result()
		if err == nil || got != nil || dec.String() != "" {
			t.Fatalf("unauthenticated data returned %x, %v", got, err)
		}
	}
	for i := range envelope {
		changed := append([]byte(nil), envelope...)
		changed[i] ^= 1
		assertRejected(changed, key)
	}
	for n := 0; n < len(envelope); n++ {
		assertRejected(envelope[:n], key)
	}
	assertRejected(append(append([]byte(nil), envelope...), 0), key)
	assertRejected(envelope, []byte("87654321"))
}

func TestDESRejectsInvalidKeys(t *testing.T) {
	for _, size := range []int{0, 1, 7, 9, 16} {
		for _, method := range []func(*cryptoutils.CryptoData) *cryptoutils.CryptoData{
			(*cryptoutils.CryptoData).DesCBCEncrypt,
			(*cryptoutils.CryptoData).DesDecrypt,
			(*cryptoutils.CryptoData).DesDecryptLegacy,
		} {
			data := cryptoutils.Init("12345678")
			data.SetKey(make([]byte, size))
			if got, err := method(data).Result(); err == nil || got != nil {
				t.Fatalf("%d byte key returned %x, %v", size, got, err)
			}
		}
	}
}

func TestDESLegacyFixedVector(t *testing.T) {
	// Captured from the original key-as-IV implementation before migration.
	envelope := cryptoTestHex(t, "0b2a92e81fb49ce1a43266aacaea7b81")
	key := []byte("12345678")
	dec := cryptoutils.Init(envelope)
	dec.SetKey(key)
	got, err := dec.DesDecryptLegacy().Result()
	if err != nil || string(got) != "hello world" {
		t.Fatalf("legacy decrypt = %q, %v", got, err)
	}
	modern := cryptoutils.Init(envelope)
	modern.SetKey(key)
	if got, err := modern.DesDecrypt().Result(); err == nil || got != nil {
		t.Fatalf("modern decrypt silently accepted legacy data: %x, %v", got, err)
	}
}

func TestDESLegacyRejectsMalformedInput(t *testing.T) {
	key := []byte("12345678")
	block, err := des.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	badPadding := make([]byte, 8)
	cipher.NewCBCEncrypter(block, key).CryptBlocks(badPadding, make([]byte, 8))
	for _, input := range [][]byte{nil, {1}, make([]byte, 7), make([]byte, 9), badPadding} {
		dec := cryptoutils.Init(input)
		dec.SetKey(key)
		if got, err := dec.DesDecryptLegacy().Result(); err == nil || got != nil {
			t.Fatalf("invalid legacy data %x returned %x, %v", input, got, err)
		}
	}
}

func TestCipherMethodsPreservePriorErrors(t *testing.T) {
	data := cryptoutils.Init(123)
	firstErr := data.Err()
	if firstErr == nil {
		t.Fatal("expected an initialization error")
	}
	data.SetKey([]byte("12345678"))
	data.DesCBCEncrypt().DesDecrypt().DesDecryptLegacy().AESGCMEncrypt(nil).AESGCMDecrypt(nil)
	if got, err := data.Result(); err != firstErr || got != nil {
		t.Fatalf("prior error overwritten: %x, %v; want %v", got, err, firstErr)
	}
}

func cryptoTestHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
