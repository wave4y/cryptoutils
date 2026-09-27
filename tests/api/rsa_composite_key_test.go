package cryptoutils_test

import (
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"

	c "github.com/wave4y/cryptoutils"
)

func compositeRSAFixture(t *testing.T, swap bool) *rsa.PrivateKey {
	t.Helper()
	one := big.NewInt(1)
	// The Mersenne prime 2^1279 - 1 and the composite 3 * (2^768 + 1)
	// pass the product/exponent consistency checks in rsa.PrivateKey.Validate.
	p := new(big.Int).Sub(new(big.Int).Lsh(one, 1279), one)
	q := new(big.Int).Mul(big.NewInt(3), new(big.Int).Add(new(big.Int).Lsh(one, 768), one))
	n := new(big.Int).Mul(p, q)
	fakePhi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
	d := new(big.Int).ModInverse(big.NewInt(65537), fakePhi)
	if d == nil || n.BitLen() < 2048 || new(big.Int).Mod(q, big.NewInt(3)).Sign() != 0 {
		t.Fatal("invalid composite-key fixture")
	}
	if swap {
		p, q = q, p
	}
	return &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: n, E: 65537}, D: d, Primes: []*big.Int{p, q}}
}

func TestRSARejectsCompositePrivateFactors(t *testing.T) {
	for _, tt := range []struct {
		name string
		swap bool
	}{{"composite_q", false}, {"composite_p", true}} {
		t.Run(tt.name, func(t *testing.T) {
			key := compositeRSAFixture(t, tt.swap)
			// Construct malformed inputs independently of cryptoutils' validated
			// exporters, so import rejection remains covered after this fix.
			one := big.NewInt(1)
			pkcs1, err := asn1.Marshal(struct {
				Version               int
				N                     *big.Int
				E                     int
				D, P, Q, DP, DQ, Qinv *big.Int
			}{
				0, key.N, key.E, key.D, key.Primes[0], key.Primes[1],
				new(big.Int).Mod(key.D, new(big.Int).Sub(key.Primes[0], one)),
				new(big.Int).Mod(key.D, new(big.Int).Sub(key.Primes[1], one)),
				new(big.Int).ModInverse(key.Primes[1], key.Primes[0]),
			})
			if err != nil {
				t.Fatal(err)
			}
			pkcs8, err := asn1.Marshal(struct {
				Version    int
				Algorithm  pkix.AlgorithmIdentifier
				PrivateKey []byte
			}{0, pkix.AlgorithmIdentifier{
				Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}, Parameters: asn1.NullRawValue,
			}, pkcs1})
			if err != nil {
				t.Fatal(err)
			}
			pkcs1PEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: pkcs1})
			pkcs8PEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
			original := []*big.Int{
				new(big.Int).Set(key.N), new(big.Int).Set(key.D),
				new(big.Int).Set(key.Primes[0]), new(big.Int).Set(key.Primes[1]),
			}
			// A rejected key must not cause caller-owned CRT caches to be rebuilt.
			key.Precomputed = rsa.PrecomputedValues{Dp: big.NewInt(111), Dq: big.NewInt(222), Qinv: big.NewInt(333)}
			cached := key.Precomputed
			for _, operation := range []struct {
				name string
				run  func() error
			}{
				{"marshal_der", func() error { _, err := c.MarshalPrivateKeyDER(key); return err }},
				{"marshal_pem", func() error { _, err := c.MarshalPrivateKeyPEM(key); return err }},
				{"parse_pkcs1_der", func() error { _, err := c.ParsePrivateKeyDER(pkcs1); return err }},
				{"parse_pkcs8_der", func() error { _, err := c.ParsePrivateKeyDER(pkcs8); return err }},
				{"parse_pkcs1_pem", func() error { _, err := c.ParsePrivateKeyPEM(pkcs1PEM); return err }},
				{"parse_pkcs8_pem", func() error { _, err := c.ParsePrivateKeyPEM(pkcs8PEM); return err }},
				{"sign_pss", func() error { _, err := c.SignRSAPSS([]byte("message"), key); return err }},
				{"decrypt_oaep", func() error { _, err := c.DecryptRSAOAEP(make([]byte, key.Size()), key, nil); return err }},
			} {
				t.Run(operation.name, func(t *testing.T) {
					if err := operation.run(); !errors.Is(err, c.ErrInvalidAsymmetricKey) {
						t.Fatalf("got %v, want ErrInvalidAsymmetricKey", err)
					}
				})
			}
			for i, value := range []*big.Int{key.N, key.D, key.Primes[0], key.Primes[1]} {
				if value.Cmp(original[i]) != 0 {
					t.Fatal("rejection mutated caller-owned RSA parameters")
				}
			}
			if key.Precomputed.Dp != cached.Dp || key.Precomputed.Dq != cached.Dq || key.Precomputed.Qinv != cached.Qinv ||
				key.Precomputed.Dp.Int64() != 111 || key.Precomputed.Dq.Int64() != 222 || key.Precomputed.Qinv.Int64() != 333 {
				t.Fatal("rejection mutated caller-owned CRT caches")
			}
		})
	}
}
