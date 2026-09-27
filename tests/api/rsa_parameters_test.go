package cryptoutils_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"

	c "github.com/wave4y/cryptoutils"
)

func TestRSAParameterWorkflow(t *testing.T) {
	der := x509.MarshalPKCS1PublicKey(&rsa.PublicKey{N: big.NewInt(3233), E: 17})
	encoded := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: der})
	public, err := c.ParseRSAPublicParametersPEM(encoded)
	if err != nil {
		t.Fatal(err)
	}
	private, err := c.RSACompletePrivateParameters(big.NewInt(61), big.NewInt(53), public.E)
	if err != nil {
		t.Fatal(err)
	}
	if private.N.Cmp(public.N) != 0 || private.D.Int64() != 413 || private.Phi.Int64() != 3120 || private.Lambda.Int64() != 780 {
		t.Fatal("unexpected completed key")
	}
	message, err := c.DecryptRSARaw(public.N, private.D, big.NewInt(2790))
	if err != nil || message.Int64() != 65 {
		t.Fatalf("raw decryption: %v, %v", message, err)
	}
	crt, err := c.DecryptRSACRT(private.P, private.Q, private.DP, private.DQ, big.NewInt(2790))
	if err != nil || crt.Cmp(message) != 0 {
		t.Fatalf("CRT decryption: %v, %v", crt, err)
	}
	phiD, err := c.RSAPrivateExponent(public.E, private.Phi)
	if err != nil || phiD.Int64() != 2753 {
		t.Fatalf("phi exponent: %v, %v", phiD, err)
	}
	if _, err := c.ParsePublicKeyPEM(encoded); !errors.Is(err, c.ErrInvalidAsymmetricKey) {
		t.Fatal("CTF parsing changed standard RSA import policy")
	}
	if _, err := c.RSACompletePrivateParameters(big.NewInt(9), big.NewInt(53), public.E); !errors.Is(err, c.ErrInvalidRSACTFInput) {
		t.Fatal("composite factor accepted")
	}
	if _, err := c.RSAPrivateExponent(big.NewInt(6), private.Phi); !errors.Is(err, c.ErrRSACTFNoResult) {
		t.Fatal("noninvertible exponent accepted")
	}
}

func TestRSAParametersLargeExponent(t *testing.T) {
	e := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(780), 80), big.NewInt(17))
	der, err := asn1.Marshal(struct{ N, E *big.Int }{big.NewInt(3233), e})
	if err != nil {
		t.Fatal(err)
	}
	public, err := c.ParseRSAPublicParametersDER(der)
	if err != nil || public.E.Cmp(e) != 0 {
		t.Fatalf("large exponent parse: %v, %v", public, err)
	}
	private, err := c.RSACompletePrivateParameters(big.NewInt(61), big.NewInt(53), public.E)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := c.EncryptRSARaw(public.N, public.E, big.NewInt(65))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := c.DecryptRSARaw(private.N, private.D, ciphertext)
	if err != nil || plaintext.Int64() != 65 {
		t.Fatalf("large exponent round trip: %v, %v", plaintext, err)
	}
}
