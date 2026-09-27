package cryptoutils_test

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"fmt"
	c "github.com/wave4y/cryptoutils"
	"testing"
)

func TestDESCBCEnvelopeRoundTrip(t *testing.T) {
	key := []byte("12345678")
	for _, plaintext := range []string{"", "a", "12345678", "hello world"} {
		t.Run(fmt.Sprintf("length=%d", len(plaintext)), func(t *testing.T) {
			enc := c.Init(plaintext)
			enc.SetKey(key)
			envelope, err := enc.DesCBCEncrypt().Result()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.HasPrefix(envelope, []byte("CU-DES\x01")) {
				t.Fatalf("missing version prefix: %x", envelope)
			}
			dec := c.Init(envelope)
			dec.SetKey(key)
			got, err := dec.DesDecrypt().Result()
			if err != nil || string(got) != plaintext || dec.String() != plaintext {
				t.Fatalf("decrypt = %q, %v; want %q", got, err, plaintext)
			}
			second := c.Init(plaintext)
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
	enc := c.Init("secret payload")
	enc.SetKey(key)
	envelope, err := enc.DesCBCEncrypt().Result()
	if err != nil {
		t.Fatal(err)
	}
	assertRejected := func(input, key []byte) {
		t.Helper()
		dec := c.Init(input)
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
		for _, method := range []func(*c.CryptoData) *c.CryptoData{
			(*c.CryptoData).DesCBCEncrypt,
			(*c.CryptoData).DesDecrypt,
			(*c.CryptoData).DesDecryptLegacy,
		} {
			data := c.Init("12345678")
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
	dec := c.Init(envelope)
	dec.SetKey(key)
	got, err := dec.DesDecryptLegacy().Result()
	if err != nil || string(got) != "hello world" {
		t.Fatalf("legacy decrypt = %q, %v", got, err)
	}
	modern := c.Init(envelope)
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
		dec := c.Init(input)
		dec.SetKey(key)
		if got, err := dec.DesDecryptLegacy().Result(); err == nil || got != nil {
			t.Fatalf("invalid legacy data %x returned %x, %v", input, got, err)
		}
	}
}
