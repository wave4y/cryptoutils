package cryptoutils_test

import (
	"bytes"
	"encoding/hex"
	"testing"
	c "www.gitlablow.com/wave4y/cryptoutils"
)

func TestSM9RootAndChain(t *testing.T) {
	identity := []byte("Alice")
	signMaster, err := c.GenerateSM9SignMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	signKey, err := signMaster.Extract(identity)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := c.Init("message").SM9Sign(signKey).Result()
	if err != nil {
		t.Fatal(err)
	}
	if len(signature) != 96 {
		t.Fatalf("signature length %d", len(signature))
	}
	verified := c.Init("message").SM9Verify(signMaster.Public(), identity, signature)
	if verified.Err() != nil || verified.String() != "message" {
		t.Fatal("verify did not preserve message", verified.Err())
	}
	signature[40] ^= 1
	failed := c.Init("message").SM9Verify(signMaster.Public(), identity, signature)
	first := failed.Err()
	if first == nil {
		t.Fatal("bad signature accepted")
	}
	failed.SM9Sign(signKey).Hex()
	if failed.Err() != first || failed.String() != "" {
		t.Fatal("signature error not sticky")
	}
	encryptMaster, err := c.GenerateSM9EncryptMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	decryptKey, err := encryptMaster.Extract(identity)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []c.SM9EncryptionMode{c.SM9XOR, c.SM9SM4ECB} {
		encrypted, err := c.Init("message").SM9EncryptWithMode(encryptMaster.Public(), identity, mode).Hex().Result()
		if err != nil {
			t.Fatal(err)
		}
		decrypted, err := c.Init(encrypted).HexDecode().SM9DecryptWithMode(decryptKey, identity, mode).Result()
		if err != nil || string(decrypted) != "message" {
			t.Fatalf("decrypt %q %v", decrypted, err)
		}
	}
	encrypted, err := c.EncryptSM9([]byte("message"), identity, encryptMaster.Public())
	if err != nil {
		t.Fatal(err)
	}
	out, err := c.Init(encrypted).SM9Decrypt(decryptKey, identity).Result()
	if err != nil || string(out) != "message" {
		t.Fatal("XOR chain failed", err)
	}
	enc, key, err := c.EncapsulateSM9(identity, encryptMaster.Public(), 32)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := c.DecapsulateSM9(enc, identity, decryptKey, 32)
	if err != nil || !bytes.Equal(key, recovered) {
		t.Fatal("root KEM failed", err)
	}
	p := c.Init("zz").HexDecode()
	prior := p.Err()
	p.SM9Encrypt(encryptMaster.Public(), identity).SM9Decrypt(decryptKey, identity).SM9Verify(signMaster.Public(), identity, nil)
	if p.Err() != prior || p.Bytes() != nil {
		t.Fatal("prior error lost")
	}
}
func TestSM9RootFixedSignature(t *testing.T) {
	scalar := make([]byte, 32)
	value, _ := hex.DecodeString("0130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4")
	copy(scalar[32-len(value):], value)
	master, err := c.ParseSM9SignMasterPrivateKey(scalar)
	if err != nil {
		t.Fatal(err)
	}
	signature, _ := hex.DecodeString("823c4b21e4bd2dfe1ed92c606653e996668563152fc33f55d7bfbb9bd9705adb73bf96923ce58b6ad0e13e9643a406d8eb98417c50ef1b29cef9adb48b6d598c856712f1c2e0968ab7769f42a99586aed139d5b8b3e15891827cc2aced9baa05")
	if err := c.VerifySM9([]byte("Chinese IBS standard"), []byte("Alice"), signature, master.Public()); err != nil {
		t.Fatal(err)
	}
}
