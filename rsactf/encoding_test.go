package rsactf_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"

	"github.com/wave4y/cryptoutils/rsactf"
)

func rsaDERValue(t *testing.T, value interface{}) []byte {
	t.Helper()
	der, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func rsaDERSequence(t *testing.T, fields ...[]byte) []byte {
	t.Helper()
	return rsaDERValue(t, asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: bytes.Join(fields, nil)})
}

func rsaTestPKCS1(t *testing.T, n, e *big.Int) []byte {
	t.Helper()
	return rsaDERSequence(t, rsaDERValue(t, n), rsaDERValue(t, e))
}

func rsaTestAlgorithm(t *testing.T, parameters ...[]byte) []byte {
	t.Helper()
	oid := rsaDERValue(t, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1})
	return rsaDERSequence(t, append([][]byte{oid}, parameters...)...)
}

func rsaTestPKIX(t *testing.T, algorithm, public []byte) []byte {
	t.Helper()
	return rsaDERSequence(t, algorithm, rsaDERValue(t, asn1.BitString{Bytes: public, BitLength: len(public) * 8}))
}

func TestParsePublicKeyCTFParameters(t *testing.T) {
	largeE := new(big.Int).Add(new(big.Int).Lsh(integer(1), 200), integer(17))
	for _, e := range []*big.Int{integer(1), integer(2), integer(65537), largeE} {
		pkcs1 := rsaTestPKCS1(t, integer(3233), e)
		pkix := rsaTestPKIX(t, rsaTestAlgorithm(t, []byte{5, 0}), pkcs1)
		for kind, der := range map[string][]byte{"RSA PUBLIC KEY": pkcs1, "PUBLIC KEY": pkix} {
			key, err := rsactf.ParsePublicKeyDER(der)
			if err != nil || key.N.Int64() != 3233 || key.E.Cmp(e) != 0 {
				t.Fatalf("DER %s e=%s: %v, %v", kind, e, key, err)
			}
			// These values can be used directly by the existing raw API.
			got, err := rsactf.EncryptRaw(key.N, key.E, integer(65))
			want := new(big.Int).Exp(integer(65), e, integer(3233))
			if err != nil || got.Cmp(want) != 0 {
				t.Fatalf("EncryptRaw: %v, %v", got, err)
			}
			encoded := pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
			key, err = rsactf.ParsePublicKeyPEM(append(append([]byte(" \n\t"), encoded...), '\n', ' '))
			if err != nil || key.N.Int64() != 3233 || key.E.Cmp(e) != 0 {
				t.Fatalf("PEM %s e=%s: %v, %v", kind, e, key, err)
			}
		}
	}
	// An absent algorithm parameter is accepted; other non-NULL values are not.
	der := rsaTestPKIX(t, rsaTestAlgorithm(t), rsaTestPKCS1(t, integer(3233), integer(17)))
	if _, err := rsactf.ParsePublicKeyDER(der); err != nil {
		t.Fatal(err)
	}
}

func TestParsePublicKeyStandardRSA2048(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkix, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, der := range [][]byte{x509.MarshalPKCS1PublicKey(&private.PublicKey), pkix} {
		key, err := rsactf.ParsePublicKeyDER(der)
		if err != nil || key.N.Cmp(private.N) != 0 || key.E.Int64() != int64(private.E) {
			t.Fatalf("2048-bit standard key: %v, %v", key, err)
		}
		// Returned integers must remain intact when the source byte buffer changes.
		for i := range der {
			der[i] = 0
		}
		if key.N.Cmp(private.N) != 0 || key.E.Int64() != int64(private.E) {
			t.Fatal("decoded parameters alias DER input")
		}
	}
}

func TestParsePublicKeyDERRejectsInvalidEncodings(t *testing.T) {
	n, e := rsaDERValue(t, integer(3233)), rsaDERValue(t, integer(17))
	public := rsaDERSequence(t, n, e)
	algorithm := rsaTestAlgorithm(t, []byte{5, 0})
	bits := rsaDERValue(t, asn1.BitString{Bytes: public, BitLength: len(public) * 8})
	unalignedPublic := rsaTestPKCS1(t, integer(3233), integer(16))
	unalignedBits := rsaDERValue(t, asn1.BitString{Bytes: unalignedPublic, BitLength: len(unalignedPublic)*8 - 1})
	for name, der := range map[string][]byte{
		"empty":                     nil,
		"oversized":                 make([]byte, 64*1024+1),
		"truncated":                 public[:len(public)-1],
		"trailing bytes":            append(append([]byte{}, public...), 0),
		"extra integer":             rsaDERSequence(t, n, e, e),
		"missing exponent":          rsaDERSequence(t, n),
		"negative modulus":          rsaTestPKCS1(t, integer(-3233), integer(17)),
		"unit modulus":              rsaTestPKCS1(t, integer(1), integer(17)),
		"zero modulus":              rsaTestPKCS1(t, integer(0), integer(17)),
		"negative exponent":         rsaTestPKCS1(t, integer(3233), integer(-17)),
		"zero exponent":             rsaTestPKCS1(t, integer(3233), integer(0)),
		"nonminimal integer":        rsaDERSequence(t, n, []byte{2, 2, 0, 17}),
		"wrong integer tag":         rsaDERSequence(t, n, []byte{4, 1, 17}),
		"constructed integer":       rsaDERSequence(t, n, []byte{0x22, 1, 17}),
		"wrong integer class":       rsaDERSequence(t, n, []byte{0x82, 1, 17}),
		"nonminimal length":         []byte{0x30, 0x81, 7, 2, 2, 12, 161, 2, 1, 17},
		"indefinite length":         []byte{0x30, 0x80, 2, 2, 12, 161, 2, 1, 17, 0, 0},
		"non RSA algorithm":         rsaTestPKIX(t, rsaDERSequence(t, rsaDERValue(t, asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1})), public),
		"empty algorithm":           rsaTestPKIX(t, rsaDERSequence(t), public),
		"wrong algorithm parameter": rsaTestPKIX(t, rsaTestAlgorithm(t, []byte{4, 0}), public),
		"nonempty NULL":             rsaTestPKIX(t, rsaTestAlgorithm(t, []byte{5, 1, 0}), public),
		"extra algorithm parameter": rsaTestPKIX(t, rsaTestAlgorithm(t, []byte{5, 0}, []byte{5, 0}), public),
		"extra PKIX field":          rsaDERSequence(t, algorithm, bits, e),
		"missing bitstring":         rsaDERSequence(t, algorithm),
		"empty bitstring":           rsaDERSequence(t, algorithm, []byte{3, 1, 0}),
		"unaligned bitstring":       rsaDERSequence(t, algorithm, unalignedBits),
		"invalid unused bits":       rsaDERSequence(t, algorithm, []byte{3, 2, 8, 0}),
		"extra inner field":         rsaTestPKIX(t, algorithm, rsaDERSequence(t, n, e, e)),
		"trailing inner bytes":      rsaTestPKIX(t, algorithm, append(append([]byte{}, public...), 0)),
	} {
		t.Run(name, func(t *testing.T) {
			key, err := rsactf.ParsePublicKeyDER(der)
			if key != nil || !errors.Is(err, rsactf.ErrInvalidInput) {
				t.Fatalf("accepted invalid DER: %v, %v", key, err)
			}
		})
	}
}

func TestParsePublicKeyPEMRejectsInvalidEncodings(t *testing.T) {
	public := rsaTestPKCS1(t, integer(3233), integer(17))
	encoded := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: public})
	for name, data := range map[string][]byte{
		"empty":                   nil,
		"oversized":               make([]byte, 128*1024+1),
		"DER too large":           pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: make([]byte, 64*1024+1)}),
		"raw DER":                 public,
		"prefix text":             append([]byte("ignored text\n"), encoded...),
		"suffix text":             append(append([]byte{}, encoded...), []byte("ignored text")...),
		"two blocks":              append(append([]byte{}, encoded...), encoded...),
		"malformed leading block": append([]byte("-----BEGIN RSA PUBLIC KEY-----\n?\n-----END RSA PUBLIC KEY-----\n"), encoded...),
		"headers":                 pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Headers: map[string]string{"Comment": "x"}, Bytes: public}),
		"wrong label":             pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}),
		"unsupported label":       pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: public}),
		"wrong PKIX label":        pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: rsaTestPKIX(t, rsaTestAlgorithm(t, []byte{5, 0}), public)}),
	} {
		t.Run(name, func(t *testing.T) {
			key, err := rsactf.ParsePublicKeyPEM(data)
			if key != nil || !errors.Is(err, rsactf.ErrInvalidInput) {
				t.Fatalf("accepted invalid PEM: %v, %v", key, err)
			}
		})
	}
}

func FuzzParsePublicKeyDER(f *testing.F) {
	f.Add([]byte{0x30, 7, 2, 2, 12, 161, 2, 1, 17}) // n=3233, e=17
	f.Add([]byte{0x30, 0})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, der []byte) {
		key, err := rsactf.ParsePublicKeyDER(der)
		if err != nil {
			if key != nil || !errors.Is(err, rsactf.ErrInvalidInput) {
				t.Fatalf("unexpected parser error: %v, %v", key, err)
			}
			return
		}
		if key == nil || key.N == nil || key.E == nil || key.N.Cmp(integer(1)) <= 0 || key.E.Sign() <= 0 {
			t.Fatalf("accepted invalid integer parameters: %v", key)
		}
		canonical := rsaTestPKCS1(t, key.N, key.E)
		reparsed, err := rsactf.ParsePublicKeyDER(canonical)
		if err != nil || reparsed.N.Cmp(key.N) != 0 || reparsed.E.Cmp(key.E) != 0 {
			t.Fatalf("canonical reparse failed: %v", err)
		}
	})
}
