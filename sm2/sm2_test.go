package sm2

import (
	"bytes"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
)

func decode(s string) []byte {
	b, e := hex.DecodeString(s)
	if e != nil {
		panic(e)
	}
	return b
}

func TestSM2RejectsExtraASN1Fields(t *testing.T) {
	raw := make([]byte, 32)
	raw[31] = 1
	key, err := NewPrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	// Find a deterministic valid signature short enough that an appended NULL
	// still fits the existing 72-byte limit; size checks alone cannot reject it.
	found := false
	for i := 0; i < 32; i++ {
		message := []byte(fmt.Sprintf("strict DER %d", i))
		sig, err := Sign(bytes.NewReader(make([]byte, 32)), key, nil, message)
		if err != nil {
			t.Fatal(err)
		}
		if len(sig) > 70 {
			continue
		}
		if !Verify(&key.PublicKey, nil, message, sig) {
			t.Fatal("valid control signature rejected")
		}
		var rs signature
		if _, err := asn1.Unmarshal(sig, &rs); err != nil {
			t.Fatal(err)
		}
		extra, err := asn1.Marshal(struct {
			R, S  *big.Int
			Extra asn1.RawValue
		}{rs.R, rs.S, asn1.NullRawValue})
		if err != nil {
			t.Fatal(err)
		}
		if Verify(&key.PublicKey, nil, message, extra) {
			t.Fatal("signature with extra SEQUENCE field accepted")
		}
		found = true
		break
	}
	if !found {
		t.Fatal("could not create bounded-length signature fixture")
	}
	ciphertext, err := EncryptASN1(bytes.NewReader(make([]byte, 32)), &key.PublicKey, []byte("strict DER"))
	if err != nil {
		t.Fatal(err)
	}
	var parsed asn1Ciphertext
	if _, err := asn1.Unmarshal(ciphertext, &parsed); err != nil {
		t.Fatal(err)
	}
	extra, err := asn1.Marshal(struct {
		X, Y             *big.Int
		Hash, Ciphertext []byte
		Extra            asn1.RawValue
	}{parsed.X, parsed.Y, parsed.Hash, parsed.Ciphertext, asn1.NullRawValue})
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := DecryptASN1(key, extra); err == nil || plain != nil {
		t.Fatal("ciphertext with extra SEQUENCE field accepted")
	}
}
func TestSM2BasePoint(t *testing.T) {
	raw := make([]byte, 32)
	raw[31] = 1
	p, e := NewPrivateKey(raw)
	if e != nil {
		t.Fatal(e)
	}
	out, e := p.PublicKey.Bytes()
	want := "0432c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0"
	if e != nil || hex.EncodeToString(out) != want {
		t.Fatalf("base point: %x %v", out, e)
	}
}

// OpenSSL's published SM2 test fixtures, Apache-2.0:
// https://github.com/openssl/openssl/blob/master/test/recipes/30-test_evp_data/evppkey_sm2.txt
func opensslKey(t *testing.T) *PrivateKey {
	t.Helper()
	der, e := base64.StdEncoding.DecodeString("MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQg0JFWczAXva2An9m72MaT9gIwWTFptvlKrxyO4TjMmbWhRANCAAQ5OirZ4n5DrKqrhaGdO4VZHhRAYVcXWt3Te/d/8Mr57Tf886i09VwDhSMmH8pmNq/mp6+ioUgqYG9cs6GLLioe")
	if e != nil {
		t.Fatal(e)
	}
	var outer struct {
		Version int
		Algo    pkix.AlgorithmIdentifier
		Key     []byte
	}
	if _, e = asn1.Unmarshal(der, &outer); e != nil {
		t.Fatal(e)
	}
	var inner struct {
		Version int
		Key     []byte
		Curve   asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
		Public  asn1.BitString        `asn1:"optional,explicit,tag:1"`
	}
	if _, e = asn1.Unmarshal(outer.Key, &inner); e != nil {
		t.Fatal(e)
	}
	p, e := NewPrivateKey(inner.Key)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func TestOpenSSLKnownAnswers(t *testing.T) {
	p := opensslKey(t)
	hash := decode("D7AD397F6FFA5D4F7F11E7217F241607DC30618C236D2C09C1B9EA8FDADEE2E8")
	sig := decode("3046022100AB1DB64DE7C40EDBDE6651C9B8EBDB804673DB836E5D5C7FE15DCF9ED2725037022100EBA714451FF69B0BB930B379E192E7CD5FA6E3C41C7FBD8303B799AB54A54621")
	if !VerifyDigest(&p.PublicKey, hash, sig) {
		t.Fatal("OpenSSL signature rejected")
	}
	ct := decode("30818A0220466BE2EF5C11782EC77864A0055417F407A5AFC11D653C6BCE69E417BB1D05B6022062B572E21FF0DDF5C726BD3F9FF2EAE56E6294713A607E9B9525628965F62CC804203C1B5713B5DB2728EB7BF775E44F4689FC32668BDC564F52EA45B09E8DF2A5F40422084A9D0CC2997092B7D3C404FCE95956EB604D732B2307A8E5B8900ED6608CA5B197")
	plain, e := DecryptASN1(p, ct)
	if e != nil || string(plain) != "The floofy bunnies hop at midnight" {
		t.Fatalf("OpenSSL decrypt %q %v", plain, e)
	}
}
func TestSM2SignEncrypt(t *testing.T) {
	p, e := GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	msg := []byte("hello 世界")
	sig, e := Sign(rand.Reader, p, nil, msg)
	if e != nil || !Verify(&p.PublicKey, nil, msg, sig) {
		t.Fatal("signature", e)
	}
	if Verify(&p.PublicKey, []byte("other"), msg, sig) || Verify(&p.PublicKey, nil, []byte("changed"), sig) || Verify(&p.PublicKey, nil, msg, append(sig, 0)) {
		t.Fatal("invalid signature accepted")
	}
	ct, e := Encrypt(rand.Reader, &p.PublicKey, msg)
	if e != nil {
		t.Fatal(e)
	}
	plain, e := Decrypt(p, ct)
	if e != nil || !bytes.Equal(plain, msg) {
		t.Fatal("decrypt", e)
	}
	for _, i := range []int{0, 1, 64, 65, 96, len(ct) - 1} {
		bad := append([]byte{}, ct...)
		bad[i] ^= 1
		if out, e := Decrypt(p, bad); e == nil || out != nil {
			t.Fatal("tamper accepted")
		}
	}
	for _, n := range []int{0, 1, 64, 65, 96, 97} {
		if _, e := Decrypt(p, ct[:n]); e == nil {
			t.Fatal("short ciphertext accepted")
		}
	}
	ct, e = EncryptASN1(rand.Reader, &p.PublicKey, msg)
	if e != nil {
		t.Fatal(e)
	}
	plain, e = DecryptASN1(p, ct)
	if e != nil || !bytes.Equal(plain, msg) {
		t.Fatal("ASN1", e)
	}
}
func TestSM2Exchange(t *testing.T) {
	a, _ := GenerateKey(rand.Reader)
	ar, _ := GenerateKey(rand.Reader)
	b, _ := GenerateKey(rand.Reader)
	br, _ := GenerateKey(rand.Reader)
	x, e := Exchange(a, ar, &b.PublicKey, &br.PublicKey, []byte("Alice"), []byte("Bob"), true, 32)
	if e != nil {
		t.Fatal(e)
	}
	y, e := Exchange(b, br, &a.PublicKey, &ar.PublicKey, []byte("Bob"), []byte("Alice"), false, 32)
	if e != nil {
		t.Fatal(e)
	}
	ka, e := x.Confirm(y.Confirmation())
	if e != nil {
		t.Fatal(e)
	}
	kb, e := y.Confirm(x.Confirmation())
	if e != nil || !bytes.Equal(ka, kb) {
		t.Fatal("exchange", e)
	}
	if k, e := x.Confirm(make([]byte, 32)); e == nil || k != nil {
		t.Fatal("bad confirmation accepted")
	}
	if _, e := Exchange(a, a, &b.PublicKey, &br.PublicKey, nil, nil, true, 32); e == nil {
		t.Fatal("ephemeral reuse accepted")
	}
}
func TestSM2RejectsInvalid(t *testing.T) {
	for _, raw := range [][]byte{nil, make([]byte, 31), make([]byte, 32), fixed(new(big.Int).Sub(curve.N, big.NewInt(1)))} {
		if _, e := NewPrivateKey(raw); e == nil {
			t.Fatal("invalid private key")
		}
	}
	if _, e := Encrypt(nil, &PublicKey{big.NewInt(0), big.NewInt(0)}, []byte("abc")); e == nil {
		t.Fatal("invalid point")
	}
	if _, e := Sign(nil, nil, nil, nil); e == nil {
		t.Fatal("nil key")
	}
	if Verify(nil, nil, nil, nil) {
		t.Fatal("nil key verified")
	}
	p, _ := GenerateKey(nil)
	if _, e := ZA(&p.PublicKey, make([]byte, 8192)); e == nil {
		t.Fatal("oversized UID")
	}
	if _, e := GenerateKey(bytes.NewReader(nil)); e == nil {
		t.Fatal("failed entropy")
	}
}

// GM/T 0003.5-2012 Annex A/C, reproduced in OpenSSL test/sm2_internal_test.c.
func TestSM2PublishedSignEncrypt(t *testing.T) {
	key, err := NewPrivateKey(decode("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"))
	if err != nil {
		t.Fatal(err)
	}
	// rand.Int returns k-1; the algorithm maps this to the nonzero scalar k.
	entropy := decode("59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC20")
	sig, err := Sign(bytes.NewReader(entropy), key, nil, []byte("message digest"))
	if err != nil {
		t.Fatal(err)
	}
	var rs signature
	if _, err := asn1.Unmarshal(sig, &rs); err != nil {
		t.Fatal(err)
	}
	if rs.R.Cmp(integer("F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3")) != 0 || rs.S.Cmp(integer("B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA")) != 0 {
		t.Fatalf("signature %x", sig)
	}
	if !Verify(&key.PublicKey, nil, []byte("message digest"), sig) {
		t.Fatal("published signature verification")
	}
	want := decode("307c022004EBFC718E8D1798620432268E77FEB6415E2EDE0E073C0F4F640ECD2E149A73022100E858F9D81E5430A57B36DAAB8F950A3C64E6EE6A63094D99283AFF767E124DF0042059983C18F809E262923C53AEC295D30383B54E39D609D160AFCB1908D0BD8766041321886CA989CA9C7D58087307CA93092D651EFA")
	ct, err := EncryptASN1(bytes.NewReader(entropy), &key.PublicKey, []byte("encryption standard"))
	if err != nil || !bytes.Equal(ct, want) {
		t.Fatalf("published encryption: %x %v", ct, err)
	}
}
