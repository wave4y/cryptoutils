package cryptoutils_test

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"math/big"
	"sync"
	"testing"

	c "github.com/wave4y/cryptoutils"
)

var rsaFixtureOnce sync.Once
var rsaFixture *rsa.PrivateKey
var rsaFixtureError error

func publicKeyRSAFixture(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	rsaFixtureOnce.Do(func() { rsaFixture, rsaFixtureError = c.GenerateRSAKey(2048) })
	if rsaFixtureError != nil {
		t.Fatal(rsaFixtureError)
	}
	return rsaFixture
}

func publicKeyHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRSAOAEPAndPSSInteroperability(t *testing.T) {
	key := publicKeyRSAFixture(t)
	message, label := []byte("public-key message"), []byte("label")
	ciphertext, err := c.EncryptRSAOAEP(message, &key.PublicKey, label)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, ciphertext, label)
	if err != nil || !bytes.Equal(plain, message) {
		t.Fatalf("stdlib OAEP decrypt: %q %v", plain, err)
	}
	stdCipher, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, message, label)
	if err != nil {
		t.Fatal(err)
	}
	plain, err = c.DecryptRSAOAEP(stdCipher, key, label)
	if err != nil || !bytes.Equal(plain, message) {
		t.Fatal("OAEP interoperability failed")
	}
	if _, err := c.DecryptRSAOAEP(stdCipher, key, []byte("wrong")); err == nil {
		t.Fatal("wrong OAEP label accepted")
	}
	if _, err := c.EncryptRSAOAEP(make([]byte, key.Size()-65), &key.PublicKey, nil); err == nil {
		t.Fatal("oversized OAEP plaintext accepted")
	}
	if _, err := c.DecryptRSAOAEP(stdCipher[:len(stdCipher)-1], key, label); err == nil {
		t.Fatal("short OAEP ciphertext accepted")
	}
	if got := c.Init(message).RSAOAEPEncrypt(&key.PublicKey, label).RSAOAEPDecrypt(key, label); got.Err() != nil || !bytes.Equal(got.Bytes(), message) {
		t.Fatalf("OAEP chain: %v", got.Err())
	}
	sig, err := c.SignRSAPSS(message, key)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(message)
	if err := rsa.VerifyPSS(&key.PublicKey, crypto.SHA256, digest[:], sig, &rsa.PSSOptions{SaltLength: 32}); err != nil {
		t.Fatal(err)
	}
	stdSig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: 32})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.VerifyRSAPSS(message, stdSig, &key.PublicKey); err != nil {
		t.Fatal(err)
	}
	if err := c.VerifyRSAPSS([]byte("changed"), sig, &key.PublicKey); !errors.Is(err, c.ErrSignatureVerification) {
		t.Fatal("changed PSS message accepted")
	}
	if err := c.VerifyRSAPSS(message, sig[:len(sig)-1], &key.PublicKey); err == nil {
		t.Fatal("short PSS signature accepted")
	}
	if p := c.Init(message).RSAPSSVerify(&key.PublicKey, sig); p.Err() != nil || !bytes.Equal(p.Bytes(), message) {
		t.Fatal("PSS verification changed message")
	}
	if p := c.Init(message).RSAPSSSign(key); p.Err() != nil || c.VerifyRSAPSS(message, p.Bytes(), &key.PublicKey) != nil {
		t.Fatal("PSS signing chain failed")
	}
	// Corrupted caller-owned CRT caches must not panic or affect valid key fields.
	badCache := *key
	badCache.Precomputed = key.Precomputed
	badCache.Precomputed.Dp = nil
	badCache.Precomputed.Dq = nil
	badCache.Precomputed.Qinv = nil
	if sig, err := c.SignRSAPSS(message, &badCache); err != nil || c.VerifyRSAPSS(message, sig, &key.PublicKey) != nil {
		t.Fatalf("CRT cache not safely rebuilt: %v", err)
	}
}

func TestPublicKeyRejectsMalformedKeys(t *testing.T) {
	for _, bits := range []int{-1, 0, 1024, 2047, 8193, int(^uint(0) >> 1)} {
		if _, err := c.GenerateRSAKey(bits); err == nil {
			t.Fatal("invalid RSA bits accepted")
		}
	}
	key := publicKeyRSAFixture(t)
	for _, public := range []*rsa.PublicKey{nil, {}, {N: big.NewInt(3), E: 65537}, {N: key.N, E: 0}, {N: key.N, E: 2}} {
		if _, err := c.EncryptRSAOAEP(nil, public, nil); err == nil {
			t.Fatal("invalid RSA public accepted")
		}
		if err := c.VerifyRSAPSS(nil, nil, public); err == nil {
			t.Fatal("invalid RSA verify key accepted")
		}
	}
	for _, private := range []*rsa.PrivateKey{nil, {}, {PublicKey: key.PublicKey, D: nil}, {PublicKey: key.PublicKey, D: key.D, Primes: []*big.Int{nil, key.Primes[1]}}, {PublicKey: key.PublicKey, D: big.NewInt(1), Primes: key.Primes}} {
		if _, err := c.SignRSAPSS(nil, private); err == nil {
			t.Fatal("invalid RSA private accepted")
		}
		if _, err := c.DecryptRSAOAEP(nil, private, nil); err == nil {
			t.Fatal("invalid RSA decrypt key accepted")
		}
	}
	for _, public := range []*ecdsa.PublicKey{nil, {}, {Curve: elliptic.P256(), X: big.NewInt(0), Y: big.NewInt(0)}, {Curve: elliptic.P224(), X: big.NewInt(1), Y: big.NewInt(2)}} {
		if err := c.VerifyECDSA(nil, nil, public); err == nil {
			t.Fatal("invalid EC public accepted")
		}
	}
	for _, private := range []*ecdsa.PrivateKey{nil, {}, {PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()}, D: big.NewInt(1)}} {
		if _, err := c.SignECDSA(nil, private); err == nil {
			t.Fatal("invalid EC private accepted")
		}
	}
	if _, err := c.GenerateECDSAKey("P224"); err == nil {
		t.Fatal("unsupported curve accepted")
	}
	if _, _, err := c.GenerateECDHKey("unknown"); err == nil {
		t.Fatal("unsupported ECDH curve accepted")
	}
	if _, err := c.ECDH(nil, nil); err == nil {
		t.Fatal("nil ECDH accepted")
	}
	if _, err := c.ECDH(&ecdh.PrivateKey{}, &ecdh.PublicKey{}); err == nil {
		t.Fatal("zero ECDH accepted")
	}
	for _, private := range []ed25519.PrivateKey{nil, make([]byte, 32), make([]byte, 64)} {
		if _, err := c.SignEd25519(nil, private); err == nil {
			t.Fatal("invalid Ed25519 key accepted")
		}
	}
	if err := c.VerifyEd25519(nil, nil, nil); err == nil {
		t.Fatal("nil Ed25519 public accepted")
	}
}

func TestECDSAInteroperability(t *testing.T) {
	message := []byte("ECDSA message")
	for _, name := range []string{"P-256", "P384", "P521"} {
		t.Run(name, func(t *testing.T) {
			key, err := c.GenerateECDSAKey(name)
			if err != nil {
				t.Fatal(err)
			}
			var digest []byte
			switch key.Curve {
			case elliptic.P256():
				v := sha256.Sum256(message)
				digest = v[:]
			case elliptic.P384():
				v := sha512.Sum384(message)
				digest = v[:]
			default:
				v := sha512.Sum512(message)
				digest = v[:]
			}
			sig, err := c.SignECDSA(message, key)
			if err != nil || !ecdsa.VerifyASN1(&key.PublicKey, digest, sig) {
				t.Fatalf("ECDSA signature incompatible: %v", err)
			}
			stdSig, err := ecdsa.SignASN1(rand.Reader, key, digest)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.VerifyECDSA(message, stdSig, &key.PublicKey); err != nil {
				t.Fatal(err)
			}
			if err := c.VerifyECDSA([]byte("changed"), sig, &key.PublicKey); err == nil {
				t.Fatal("changed ECDSA message accepted")
			}
			if err := c.VerifyECDSA(message, append(sig, 0), &key.PublicKey); err == nil {
				t.Fatal("trailing ECDSA signature bytes accepted")
			}
			if p := c.Init(message).ECDSAVerify(&key.PublicKey, sig); p.Err() != nil || !bytes.Equal(p.Bytes(), message) {
				t.Fatal("ECDSA verify chain changed data")
			}
			if p := c.Init(message).ECDSASign(key); p.Err() != nil || c.VerifyECDSA(message, p.Bytes(), &key.PublicKey) != nil {
				t.Fatal("ECDSA signing chain failed")
			}
			bad := *key
			bad.D = big.NewInt(1)
			if _, err := c.SignECDSA(message, &bad); err == nil {
				t.Fatal("mismatched ECDSA private/public accepted")
			}
		})
	}
}

func TestEd25519RFC8032(t *testing.T) {
	// RFC 8032 section 7.1, test 1 (empty message).
	seed := publicKeyHex(t, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	public := ed25519.PublicKey(publicKeyHex(t, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"))
	want := publicKeyHex(t, "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
	private := ed25519.NewKeyFromSeed(seed)
	sig, err := c.SignEd25519(nil, private)
	if err != nil || !bytes.Equal(sig, want) {
		t.Fatalf("RFC8032 mismatch: %x %v", sig, err)
	}
	if err := c.VerifyEd25519(nil, want, public); err != nil {
		t.Fatal(err)
	}
	if err := c.VerifyEd25519([]byte("changed"), want, public); err == nil {
		t.Fatal("changed Ed25519 message accepted")
	}
	if p := c.Init(nil).Ed25519Sign(private); p.Err() != nil || !bytes.Equal(p.Bytes(), want) {
		t.Fatal("Ed25519 chain mismatch")
	}
	if p := c.Init(nil).Ed25519Verify(public, want); p.Err() != nil || len(p.Bytes()) != 0 {
		t.Fatal("Ed25519 verify chain failed")
	}
	pub, priv, err := c.GenerateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}
	sig, err = c.SignEd25519([]byte("hello"), priv)
	if err != nil || c.VerifyEd25519([]byte("hello"), sig, pub) != nil {
		t.Fatal("generated Ed25519 keys failed")
	}
}

func TestECDHRFC7748AndCurves(t *testing.T) {
	// RFC 7748 section 6.1.
	private, err := ecdh.X25519().NewPrivateKey(publicKeyHex(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
	if err != nil {
		t.Fatal(err)
	}
	public, err := ecdh.X25519().NewPublicKey(publicKeyHex(t, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))
	if err != nil {
		t.Fatal(err)
	}
	want := "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
	out, err := c.ECDH(private, public)
	if err != nil || hex.EncodeToString(out) != want {
		t.Fatalf("RFC7748: %x %v", out, err)
	}
	if p := c.Init(nil).ECDH(private, public); p.Err() != nil || p.Hex().String() != want {
		t.Fatal("ECDH chain mismatch")
	}
	zero, err := ecdh.X25519().NewPublicKey(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ECDH(private, zero); err == nil {
		t.Fatal("low-order X25519 public accepted")
	}
	for _, name := range []string{"P256", "P384", "P521", "X25519"} {
		a, ap, err := c.GenerateECDHKey(name)
		if err != nil {
			t.Fatal(err)
		}
		b, bp, err := c.GenerateECDHKey(name)
		if err != nil {
			t.Fatal(err)
		}
		ab, err := c.ECDH(a, bp)
		if err != nil {
			t.Fatal(err)
		}
		ba, err := c.ECDH(b, ap)
		if err != nil || !bytes.Equal(ab, ba) {
			t.Fatal("ECDH asymmetry")
		}
		if name != "X25519" {
			if _, err := c.ECDH(a, public); err == nil {
				t.Fatal("mismatched ECDH curves accepted")
			}
		}
	}
}

func TestElGamalFixedGroupRoundTrip(t *testing.T) {
	key, err := c.GenerateElGamalKey()
	if err != nil {
		t.Fatal(err)
	}
	if key.P.BitLen() != 2048 || !key.P.ProbablyPrime(32) || !new(big.Int).Rsh(new(big.Int).Sub(key.P, big.NewInt(1)), 1).ProbablyPrime(32) {
		t.Fatal("ElGamal group is not a 2048-bit safe prime")
	}
	for _, message := range [][]byte{nil, []byte("legacy payload"), bytes.Repeat([]byte{0xa5}, 245)} {
		ciphertext, err := c.EncryptElGamal(message, &key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := c.DecryptElGamal(ciphertext, key)
		if err != nil || !bytes.Equal(plain, message) {
			t.Fatalf("ElGamal: %x %v", plain, err)
		}
		if p := c.Init(message).ElGamalEncrypt(&key.PublicKey).ElGamalDecrypt(key); p.Err() != nil || !bytes.Equal(p.Bytes(), message) {
			t.Fatalf("ElGamal chain: %v", p.Err())
		}
		for _, bad := range [][]byte{nil, ciphertext[:511], make([]byte, 512)} {
			if _, err := c.DecryptElGamal(bad, key); err == nil {
				t.Fatal("invalid ElGamal ciphertext accepted")
			}
		}
	}
	if _, err := c.EncryptElGamal(make([]byte, 246), &key.PublicKey); err == nil {
		t.Fatal("oversized ElGamal input accepted")
	}
	if _, err := c.EncryptElGamal(nil, nil); err == nil {
		t.Fatal("nil ElGamal public accepted")
	}
	if _, err := c.DecryptElGamal(nil, nil); err == nil {
		t.Fatal("nil ElGamal private accepted")
	}
	bad := key.PublicKey
	bad.P = big.NewInt(23)
	if _, err := c.EncryptElGamal(nil, &bad); err == nil {
		t.Fatal("arbitrary ElGamal group accepted")
	}
}

func TestAsymmetricStickyErrors(t *testing.T) {
	p := c.Init("message").Hash("unsupported")
	first := p.Err()
	p.RSAOAEPEncrypt(nil, nil).RSAOAEPDecrypt(nil, nil).RSAPSSSign(nil).RSAPSSVerify(nil, nil).ECDSASign(nil).ECDSAVerify(nil, nil).Ed25519Sign(nil).Ed25519Verify(nil, nil).ECDH(nil, nil).ElGamalEncrypt(nil).ElGamalDecrypt(nil)
	if first == nil || p.Err() != first || p.Bytes() != nil {
		t.Fatal("asymmetric operation lost sticky error")
	}
	for _, f := range []func(*c.CryptoData) *c.CryptoData{
		func(p *c.CryptoData) *c.CryptoData { return p.RSAOAEPEncrypt(nil, nil) }, func(p *c.CryptoData) *c.CryptoData { return p.RSAOAEPDecrypt(nil, nil) },
		func(p *c.CryptoData) *c.CryptoData { return p.RSAPSSSign(nil) }, func(p *c.CryptoData) *c.CryptoData { return p.RSAPSSVerify(nil, nil) },
		func(p *c.CryptoData) *c.CryptoData { return p.ECDSASign(nil) }, func(p *c.CryptoData) *c.CryptoData { return p.ECDSAVerify(nil, nil) },
		func(p *c.CryptoData) *c.CryptoData { return p.Ed25519Sign(nil) }, func(p *c.CryptoData) *c.CryptoData { return p.Ed25519Verify(nil, nil) },
		func(p *c.CryptoData) *c.CryptoData { return p.ECDH(nil, nil) }, func(p *c.CryptoData) *c.CryptoData { return p.ElGamalEncrypt(nil) }, func(p *c.CryptoData) *c.CryptoData { return p.ElGamalDecrypt(nil) },
	} {
		p := f(c.Init("message"))
		if p.Err() == nil || p.Bytes() != nil {
			t.Fatal("asymmetric failure not stored")
		}
	}
}
