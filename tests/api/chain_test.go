package cryptoutils_test

import (
	"bytes"
	"encoding/hex"
	c "github.com/wave4y/cryptoutils"
	"testing"
)

func TestCipherMethodsPreservePriorErrors(t *testing.T) {
	data := c.Init(123)
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

func TestNewCryptoChainContracts(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	iv := bytes.Repeat([]byte{8}, 16)
	p := c.Init("abc")
	p.SetKey(key)
	if got, err := p.SM4CBCEncrypt(iv).Hex().HexDecode().SM4CBCDecrypt(iv).Result(); err != nil || string(got) != "abc" {
		t.Fatal("SM4 chain", err)
	}
	if got, err := p.Reset().ZUCEncrypt(iv).ZUCDecrypt(iv).Result(); err != nil || string(got) != "abc" {
		t.Fatal("ZUC chain", err)
	}
	tag, err := c.ZUCMAC([]byte("abc"), key, iv, 4)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := p.Reset().ZUCMAC(iv, 4).Result(); err != nil || string(got) != hex.EncodeToString(tag) {
		t.Fatal("MAC chain", err)
	}
	if got, err := p.Reset().SM4CCMEncrypt(nil).SM4CCMDecrypt(nil).Result(); err != nil || string(got) != "abc" {
		t.Fatal("CCM chain", err)
	}
	for _, f := range []func(*c.CryptoData) *c.CryptoData{
		func(p *c.CryptoData) *c.CryptoData { return p.BlockEncrypt("sm4", "cbc", iv) },
		func(p *c.CryptoData) *c.CryptoData { return p.BlockDecrypt("aes", "cbc", iv) },
		func(p *c.CryptoData) *c.CryptoData { return p.AEADEncrypt("sm4-gcm", nil) },
		func(p *c.CryptoData) *c.CryptoData { return p.XTSEncrypt("aes", 0) },
		func(p *c.CryptoData) *c.CryptoData { return p.ZUCEncrypt(iv) },
		func(p *c.CryptoData) *c.CryptoData { return p.ZUCMAC(iv, 4) },
		func(p *c.CryptoData) *c.CryptoData { return p.SM2Encrypt(nil) },
	} {
		bad := c.Init(123)
		first := bad.Err()
		if got := f(bad); got.Err() != first || got.Bytes() != nil {
			t.Fatal("error overwritten")
		}
	}
	private, err := c.GenerateSM2Key()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := c.Init("message").SM2Sign(private, nil).Result()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := c.Init("message").SM2Verify(&private.PublicKey, nil, sig).Result(); err != nil || string(got) != "message" {
		t.Fatal("SM2 verify", err)
	}
	if got, err := c.Init("wrong").SM2Verify(&private.PublicKey, nil, sig).Result(); err == nil || got != nil {
		t.Fatal("SM2 failure leaked data")
	}
	if got, err := c.Init("message").SM2Encrypt(&private.PublicKey).SM2Decrypt(private).Result(); err != nil || string(got) != "message" {
		t.Fatal("SM2 chain", err)
	}
}
