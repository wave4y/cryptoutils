package cryptoutils_test

import (
	"bytes"
	"testing"
	c "www.gitlablow.com/wave4y/cryptoutils"
)

func TestMLKEMRootAPI(t *testing.T) {
	for _, parameter := range []c.MLKEMParameter{c.MLKEM512, c.MLKEM768, c.MLKEM1024} {
		pk, sk, err := c.GenerateMLKEMKey(parameter)
		if err != nil {
			t.Fatal(err)
		}
		encodedPublic, encodedPrivate := pk.Bytes(), sk.Bytes()
		public, err := c.ParseMLKEMPublicKey(parameter, encodedPublic)
		if err != nil {
			t.Fatal(err)
		}
		private, err := c.ParseMLKEMPrivateKey(parameter, encodedPrivate)
		if err != nil {
			t.Fatal(err)
		}
		ct, secret, err := c.EncapsulateMLKEM(public)
		if err != nil {
			t.Fatal(err)
		}
		recovered, err := c.DecapsulateMLKEM(ct, private)
		if err != nil || len(secret) != 32 || !bytes.Equal(recovered, secret) {
			t.Fatal("KEM agreement", err)
		}
		ct[0] ^= 1
		rejected, err := c.DecapsulateMLKEM(ct, private)
		if err != nil || bytes.Equal(rejected, secret) || len(rejected) != 32 {
			t.Fatal("KEM implicit rejection", err)
		}
		if _, err := c.DecapsulateMLKEM(ct[:len(ct)-1], private); err == nil {
			t.Fatal("short ciphertext")
		}
		if _, err := c.ParseMLKEMPublicKey(parameter, append(encodedPublic, 0)); err == nil {
			t.Fatal("trailing public key")
		}
		if _, err := c.ParseMLKEMPrivateKey(parameter, append(encodedPrivate, 0)); err == nil {
			t.Fatal("trailing private key")
		}
		encodedPublic[0] ^= 1
		encodedPrivate[0] ^= 1
		if bytes.Equal(pk.Bytes(), encodedPublic) || bytes.Equal(sk.Bytes(), encodedPrivate) {
			t.Fatal("key Bytes aliases internal state")
		}
	}
	if _, _, err := c.GenerateMLKEMKey("unknown"); err == nil {
		t.Fatal("unknown KEM")
	}
	if _, _, err := c.EncapsulateMLKEM(nil); err == nil {
		t.Fatal("nil public key")
	}
	if _, err := c.DecapsulateMLKEM(nil, nil); err == nil {
		t.Fatal("nil private key")
	}
}

func TestPQSignatureRootChains(t *testing.T) {
	for _, parameter := range []c.PQSignatureParameter{c.MLDSA65, c.SLHDSASHAKE128f} {
		pk, sk, err := c.GeneratePQSignatureKey(parameter)
		if err != nil {
			t.Fatal(err)
		}
		context := []byte("cryptoutils:test:v1")
		sig, err := c.Init("hello").PQSign(parameter, sk, context).Base64Encode().Base64Decode().Result()
		if err != nil {
			t.Fatal(err)
		}
		if got, err := c.Init("hello").PQVerify(parameter, pk, sig, context).Result(); err != nil || string(got) != "hello" {
			t.Fatal("signature verification", err)
		}
		if err := c.VerifyPQ(parameter, []byte("hello"), pk, sig, []byte("different")); err == nil {
			t.Fatal("context ignored")
		}
		sig[len(sig)-1] ^= 1
		if got, err := c.Init("hello").PQVerify(parameter, pk, sig, context).Result(); err == nil || got != nil {
			t.Fatal("bad signature accepted")
		}
		if _, err := c.SignPQ(parameter, nil, sk, make([]byte, 256)); err == nil {
			t.Fatal("oversized context")
		}
		if _, err := c.SignPQ(parameter, nil, nil, nil); err == nil {
			t.Fatal("empty private key")
		}
	}
	for _, f := range []func(*c.CryptoData) *c.CryptoData{
		func(p *c.CryptoData) *c.CryptoData { return p.MLDSASign(c.MLDSA44, nil, nil) },
		func(p *c.CryptoData) *c.CryptoData { return p.MLDSAVerify(c.MLDSA44, nil, nil, nil) },
		func(p *c.CryptoData) *c.CryptoData { return p.SLHDSASign(c.SLHDSASHA2128f, nil, nil) },
		func(p *c.CryptoData) *c.CryptoData { return p.SLHDSAVerify(c.SLHDSASHA2128f, nil, nil, nil) },
	} {
		p := c.Init(123)
		want := p.Err()
		if got := f(p); got.Err() != want || got.Bytes() != nil {
			t.Fatal("sticky error overwritten")
		}
	}
	if _, _, err := c.GenerateMLDSAKey(c.SLHDSASHA2128s); err == nil {
		t.Fatal("ML-DSA accepted SLH parameter")
	}
	if _, _, err := c.GenerateSLHDSAKey(c.MLDSA44); err == nil {
		t.Fatal("SLH accepted ML parameter")
	}
	if p := c.Init("a").MLDSASign(c.SLHDSASHA2128f, nil, nil); p.Err() == nil || p.Bytes() != nil {
		t.Fatal("wrong family")
	}
	if p := c.Init("a").SLHDSAVerify(c.MLDSA44, nil, nil, nil); p.Err() == nil || p.Bytes() != nil {
		t.Fatal("wrong family")
	}
}
