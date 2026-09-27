package cryptoutils_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"

	c "www.gitlablow.com/wave4y/cryptoutils"
)

func TestPEMDERRoundTripAndInteroperability(t *testing.T) {
	rsaKey := publicKeyRSAFixture(t)
	keys := []struct {
		name    string
		private crypto.PrivateKey
		public  crypto.PublicKey
	}{{"RSA", rsaKey, &rsaKey.PublicKey}}
	for _, name := range []string{"P256", "P384", "P521"} {
		key, err := c.GenerateECDSAKey(name)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, struct {
			name    string
			private crypto.PrivateKey
			public  crypto.PublicKey
		}{name, key, &key.PublicKey})
	}
	edPublic, edPrivate, err := c.GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}
	keys = append(keys, struct {
		name    string
		private crypto.PrivateKey
		public  crypto.PublicKey
	}{"Ed25519", edPrivate, edPublic})
	xPrivate, xPublic, err := c.GenerateECDHKey("X25519")
	if err != nil {
		t.Fatal(err)
	}
	keys = append(keys, struct {
		name    string
		private crypto.PrivateKey
		public  crypto.PublicKey
	}{"X25519", xPrivate, xPublic})
	for _, tt := range keys {
		t.Run(tt.name, func(t *testing.T) {
			privateDER, err := c.MarshalPrivateKeyDER(tt.private)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := x509.ParsePKCS8PrivateKey(privateDER); err != nil {
				t.Fatal(err)
			}
			parsedPrivate, err := c.ParsePrivateKeyDER(privateDER)
			if err != nil {
				t.Fatal(err)
			}
			again, err := c.MarshalPrivateKeyDER(parsedPrivate)
			if err != nil || !bytes.Equal(again, privateDER) {
				t.Fatal("private DER changed")
			}
			privatePEM, err := c.MarshalPrivateKeyPEM(tt.private)
			if err != nil {
				t.Fatal(err)
			}
			parsedPrivate, err = c.ParsePrivateKeyPEM(privatePEM)
			if err != nil {
				t.Fatal(err)
			}
			again, err = c.MarshalPrivateKeyDER(parsedPrivate)
			if err != nil || !bytes.Equal(again, privateDER) {
				t.Fatal("private PEM changed key")
			}
			publicDER, err := c.MarshalPublicKeyDER(tt.public)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := x509.ParsePKIXPublicKey(publicDER); err != nil {
				t.Fatal(err)
			}
			parsedPublic, err := c.ParsePublicKeyDER(publicDER)
			if err != nil {
				t.Fatal(err)
			}
			again, err = c.MarshalPublicKeyDER(parsedPublic)
			if err != nil || !bytes.Equal(again, publicDER) {
				t.Fatal("public DER changed")
			}
			publicPEM, err := c.MarshalPublicKeyPEM(tt.public)
			if err != nil {
				t.Fatal(err)
			}
			parsedPublic, err = c.ParsePublicKeyPEM(publicPEM)
			if err != nil {
				t.Fatal(err)
			}
			again, err = c.MarshalPublicKeyDER(parsedPublic)
			if err != nil || !bytes.Equal(again, publicDER) {
				t.Fatal("public PEM changed key")
			}
			if _, err := c.ParsePrivateKeyDER(append(append([]byte(nil), privateDER...), 0)); err == nil {
				t.Fatal("trailing private DER accepted")
			}
			if _, err := c.ParsePublicKeyDER(append(append([]byte(nil), publicDER...), 0)); err == nil {
				t.Fatal("trailing public DER accepted")
			}
		})
	}
}

func TestPEMLegacyContainers(t *testing.T) {
	key := publicKeyRSAFixture(t)
	privateDER := x509.MarshalPKCS1PrivateKey(key)
	if _, err := c.ParsePrivateKeyDER(privateDER); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ParsePrivateKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateDER})); err != nil {
		t.Fatal(err)
	}
	publicDER := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	if _, err := c.ParsePublicKeyDER(publicDER); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ParsePublicKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: publicDER})); err != nil {
		t.Fatal(err)
	}
	ec, err := c.GenerateECDSAKey("P256")
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalECPrivateKey(ec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ParsePrivateKeyDER(ecDER); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ParsePrivateKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER})); err != nil {
		t.Fatal(err)
	}
}

func TestECDHKeyContainers(t *testing.T) {
	for _, name := range []string{"P256", "P384", "P521", "X25519"} {
		private, public, err := c.GenerateECDHKey(name)
		if err != nil {
			t.Fatal(err)
		}
		der, err := c.MarshalPrivateKeyDER(private)
		if err != nil {
			t.Fatal(err)
		}
		parsedPrivate, err := c.ParseECDHPrivateKeyDER(der)
		if err != nil || !parsedPrivate.Equal(private) {
			t.Fatalf("ECDH private %s: %v", name, err)
		}
		encoded, err := c.MarshalPrivateKeyPEM(private)
		if err != nil {
			t.Fatal(err)
		}
		parsedPrivate, err = c.ParseECDHPrivateKeyPEM(encoded)
		if err != nil || !parsedPrivate.Equal(private) {
			t.Fatal("ECDH private PEM changed key")
		}
		der, err = c.MarshalPublicKeyDER(public)
		if err != nil {
			t.Fatal(err)
		}
		parsedPublic, err := c.ParseECDHPublicKeyDER(der)
		if err != nil || !parsedPublic.Equal(public) {
			t.Fatal("ECDH public DER changed key")
		}
		encoded, err = c.MarshalPublicKeyPEM(public)
		if err != nil {
			t.Fatal(err)
		}
		parsedPublic, err = c.ParseECDHPublicKeyPEM(encoded)
		if err != nil || !parsedPublic.Equal(public) {
			t.Fatal("ECDH public PEM changed key")
		}
	}
}

func TestKeyContainersRejectMalformedInput(t *testing.T) {
	for _, key := range []crypto.PrivateKey{nil, (*rsa.PrivateKey)(nil), (*ecdsa.PrivateKey)(nil), ed25519.PrivateKey{}, "unknown"} {
		if _, err := c.MarshalPrivateKeyDER(key); err == nil {
			t.Fatal("invalid private key marshaled")
		}
		if _, err := c.MarshalPrivateKeyPEM(key); err == nil {
			t.Fatal("invalid private key PEM marshaled")
		}
	}
	for _, key := range []crypto.PublicKey{nil, (*rsa.PublicKey)(nil), (*ecdsa.PublicKey)(nil), ed25519.PublicKey{}, "unknown"} {
		if _, err := c.MarshalPublicKeyDER(key); err == nil {
			t.Fatal("invalid public key marshaled")
		}
		if _, err := c.MarshalPublicKeyPEM(key); err == nil {
			t.Fatal("invalid public key PEM marshaled")
		}
	}
	for _, der := range [][]byte{nil, {0x30, 0}, []byte("not DER"), make([]byte, c.MaxKeyDERSize+1)} {
		if _, err := c.ParsePrivateKeyDER(der); err == nil {
			t.Fatal("invalid private DER parsed")
		}
		if _, err := c.ParsePublicKeyDER(der); err == nil {
			t.Fatal("invalid public DER parsed")
		}
		if _, err := c.ParseECDHPrivateKeyDER(der); err == nil {
			t.Fatal("invalid ECDH private DER parsed")
		}
		if _, err := c.ParseECDHPublicKeyDER(der); err == nil {
			t.Fatal("invalid ECDH public DER parsed")
		}
	}
	key := publicKeyRSAFixture(t)
	valid, err := c.MarshalPrivateKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	validPublic, err := c.MarshalPublicKeyPEM(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{nil, []byte("garbage"), append(append([]byte(nil), valid...), valid...), append([]byte("prefix"), valid...), append(append([]byte(nil), valid...), []byte("trailing")...), make([]byte, c.MaxKeyPEMSize+1), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: []byte{1}})} {
		if _, err := c.ParsePrivateKeyPEM(bad); err == nil {
			t.Fatal("invalid private PEM parsed")
		}
		if _, err := c.ParsePublicKeyPEM(bad); err == nil {
			t.Fatal("invalid public PEM parsed")
		}
		if _, err := c.ParseECDHPrivateKeyPEM(bad); err == nil {
			t.Fatal("invalid ECDH private PEM parsed")
		}
		if _, err := c.ParseECDHPublicKeyPEM(bad); err == nil {
			t.Fatal("invalid ECDH public PEM parsed")
		}
	}
	if _, err := c.ParsePrivateKeyPEM(validPublic); err == nil {
		t.Fatal("public PEM used as private")
	}
	if _, err := c.ParsePublicKeyPEM(valid); err == nil {
		t.Fatal("private PEM used as public")
	}
	if _, err := c.ParseECDHPrivateKeyPEM(valid); err == nil {
		t.Fatal("RSA used as ECDH")
	}
	if _, err := c.ParseECDHPublicKeyPEM(validPublic); err == nil {
		t.Fatal("RSA public used as ECDH")
	}
	// RSA integers are bounded before the standard parser's CRT arithmetic.
	oversized := struct {
		Version               int
		N                     *big.Int
		E                     int
		D, P, Q, DP, DQ, Qinv *big.Int
	}{0, new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 100000), big.NewInt(1)), 65537, big.NewInt(1), big.NewInt(3), big.NewInt(5), big.NewInt(1), big.NewInt(1), big.NewInt(1)}
	der, err := asn1.Marshal(oversized)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ParsePrivateKeyDER(der); err == nil {
		t.Fatal("oversized RSA modulus parsed")
	}
}
