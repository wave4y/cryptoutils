package sm9

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func scalarHex(t *testing.T, s string) []byte {
	t.Helper()
	b := unhex(t, s)
	if len(b) > 32 {
		t.Fatal("long scalar")
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}
func requireHex(t *testing.T, got []byte, want string) {
	t.Helper()
	if !bytes.Equal(got, unhex(t, want)) {
		t.Fatalf("got %x\nwant %s", got, want)
	}
}

const testEncryptMaster = "01EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22"
const testEncryptPublic = "787ed7b8a51f3ab84e0a66003f32da5c720b17eca7137d39abc66e3c80a892ff769de61791e5adc4b9ff85a31354900b202871279a8c49dc3f220f644c57a7b1"
const testEncryptPrivate = "94736acd2c8c8796cc4785e938301a139a059d3537b6414140b2d31eecf41683115bae85f5d8bc6c3dbd9e5342979acccf3c2f4f28420b1cb4f8c0b59a19b1587aa5e47570da7600cd760a0cf7beaf71c447f3844753fe74fa7ba92ca7d3b55f27538a62e7f7bfb51dce08704796d94c9d56734f119ea44732b50e31cdeb75c1"

// Values from SM9's published examples, independently recorded in the
// emmansun/gmsm v0.29.8 SM9 Appendix A/C/D known-answer tests.
func TestStandardSignature(t *testing.T) {
	requireHex(t, scalarBytes(h1([]byte("Alice"), 1)), "2acc468c3926b0bdb2767e99ff26e084de9ced8dbc7d5fbf418027b667862fab")
	master, err := NewSignMasterPrivateKey(scalarHex(t, "0130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := master.Extract([]byte("Alice"))
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.NewReader(scalarHex(t, "033c8616b06704813203dfd00965022ed15975c662337aed648835dc4b1cbe"))
	sig, err := Sign(nonce, key, []byte("Chinese IBS standard"))
	if err != nil {
		t.Fatal(err)
	}
	requireHex(t, sig, "823c4b21e4bd2dfe1ed92c606653e996668563152fc33f55d7bfbb9bd9705adb73bf96923ce58b6ad0e13e9643a406d8eb98417c50ef1b29cef9adb48b6d598c856712f1c2e0968ab7769f42a99586aed139d5b8b3e15891827cc2aced9baa05")
	if err := Verify(master.Public(), []byte("Alice"), []byte("Chinese IBS standard"), sig); err != nil {
		t.Fatal(err)
	}
	pubBytes, _ := master.Public().MarshalBinary()
	pub, err := NewSignMasterPublicKey(pubBytes)
	if err != nil {
		t.Fatal(err)
	}
	privateBytes, _ := key.MarshalBinary()
	imported, err := NewSignPrivateKey(privateBytes, []byte("Alice"), pub)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Sign(rand.Reader, imported, []byte("message"))
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(pub, []byte("Alice"), []byte("message"), again); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSignPrivateKey(privateBytes, []byte("Bob"), pub); err == nil {
		t.Fatal("accepted wrong private-key identity")
	}
	for _, i := range []int{0, 31, 32, 63, 95} {
		bad := append([]byte(nil), sig...)
		bad[i] ^= 1
		if Verify(pub, []byte("Alice"), []byte("Chinese IBS standard"), bad) == nil {
			t.Fatal("accepted corrupt signature")
		}
	}
	for _, bad := range [][]byte{nil, make([]byte, 96), append([]byte(nil), sig[:95]...), append(sig, 0), append(append([]byte(nil), sig[:32]...), make([]byte, 64)...)} {
		if Verify(pub, []byte("Alice"), []byte("Chinese IBS standard"), bad) == nil {
			t.Fatal("accepted malformed signature")
		}
	}
	if Verify(pub, []byte("Bob"), []byte("Chinese IBS standard"), sig) == nil || Verify(pub, []byte("Alice"), []byte("different message"), sig) == nil {
		t.Fatal("signature not bound to identity/message")
	}
}
func encryptionFixture(t *testing.T) (*EncryptMasterPrivateKey, *EncryptPrivateKey) {
	t.Helper()
	master, err := NewEncryptMasterPrivateKey(scalarHex(t, testEncryptMaster))
	if err != nil {
		t.Fatal(err)
	}
	key, err := master.Extract([]byte("Bob"))
	if err != nil {
		t.Fatal(err)
	}
	pubBytes, _ := master.Public().MarshalBinary()
	requireHex(t, pubBytes, testEncryptPublic)
	privBytes, _ := key.MarshalBinary()
	requireHex(t, privBytes, testEncryptPrivate)
	return master, key
}
func TestStandardEncapsulation(t *testing.T) {
	master, private := encryptionFixture(t)
	nonce := bytes.NewReader(scalarHex(t, "74015F8489C01EF4270456F9E6475BFB602BDE7F33FD482AB4E3684A6722"))
	key, c, err := Encapsulate(nonce, master.Public(), []byte("Bob"), 32)
	if err != nil {
		t.Fatal(err)
	}
	requireHex(t, c, "1edee2c3f465914491de44cefb2cb434ab02c308d9dc5e2067b4fed5aaac8a0f1c9b4c435eca35ab83bb734174c0f78fde81a53374aff3b3602bbc5e37be9a4c")
	requireHex(t, key, "4ff5cf86d2ad40c8f4bac98d76abdbde0c0e2f0a829d3f911ef5b2bce0695480")
	got, err := Decapsulate(private, []byte("Bob"), c, 32)
	if err != nil || !bytes.Equal(key, got) {
		t.Fatalf("decapsulate %x %v", got, err)
	}
}
func TestStandardEncryption(t *testing.T) {
	master, key := encryptionFixture(t)
	plain := []byte("Chinese IBE standard")
	vectors := []struct {
		mode       EncryptionMode
		ciphertext string
	}{
		{XOR, "2445471164490618e1ee20528ff1d545b0f14c8bcaa44544f03dab5dac07d8ff42ffca97d57cddc05ea405f2e586feb3a6930715532b8000759f13059ed59ac0ba672387bcd6de5016a158a52bb2e7fc429197bcab70b25afee37a2b9db9f3671b5f5b0e951489682f3e64e1378cdd5da9513b1c"},
		{SM4ECB, "2445471164490618e1ee20528ff1d545b0f14c8bcaa44544f03dab5dac07d8ff42ffca97d57cddc05ea405f2e586feb3a6930715532b8000759f13059ed59ac0fd3c98dd92c44c68332675a370cceede31e0c5cd209c257601149d12b394a2bee05b6fac6f11b965268c994f00dba7a8bb00fd60583546cbdf4649250863f10a"},
	}
	for _, v := range vectors {
		nonce := bytes.NewReader(scalarHex(t, "AAC0541779C8FC45E3E2CB25C12B5D2576B2129AE8BB5EE2CBE5EC9E785C"))
		c, err := EncryptWithMode(nonce, master.Public(), []byte("Bob"), plain, v.mode)
		if err != nil {
			t.Fatal(err)
		}
		requireHex(t, c, v.ciphertext)
		got, err := DecryptWithMode(key, []byte("Bob"), c, v.mode)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("decrypt %q %v", got, err)
		}
		for _, i := range []int{0, 31, 63, 64, 95, 96, len(c) - 1} {
			bad := append([]byte(nil), c...)
			bad[i] ^= 1
			if out, err := DecryptWithMode(key, []byte("Bob"), bad, v.mode); err == nil || out != nil {
				t.Fatalf("accepted tampered byte %d", i)
			}
		}
		zeroC := append(make([]byte, 64), c[64:]...)
		if out, err := DecryptWithMode(key, []byte("Bob"), zeroC, v.mode); err == nil || out != nil {
			t.Fatal("accepted infinity C1")
		}
		if out, err := DecryptWithMode(key, []byte("Alice"), c, v.mode); err == nil || out != nil {
			t.Fatal("accepted wrong identity")
		}
	}
	pubRaw, _ := master.Public().MarshalBinary()
	pub, err := NewEncryptMasterPublicKey(pubRaw)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := key.MarshalBinary()
	imported, err := NewEncryptPrivateKey(raw, []byte("Bob"), pub)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := Encrypt(rand.Reader, pub, []byte("Bob"), plain)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Decrypt(imported, []byte("Bob"), cipher); err != nil || !bytes.Equal(got, plain) {
		t.Fatal("imported-key decrypt", err)
	}
	if _, err := NewEncryptPrivateKey(raw, []byte("Alice"), pub); err == nil {
		t.Fatal("accepted mismatched private-key identity")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func TestInvalidInputsAndOwnership(t *testing.T) {
	for _, raw := range [][]byte{nil, make([]byte, 31), make([]byte, 32), bytes.Repeat([]byte{255}, 32), make([]byte, 33)} {
		if _, err := NewSignMasterPrivateKey(raw); err == nil {
			t.Fatal("accepted invalid sign master")
		}
		if _, err := NewEncryptMasterPrivateKey(raw); err == nil {
			t.Fatal("accepted invalid encrypt master")
		}
	}
	for _, raw := range [][]byte{nil, make([]byte, 64), make([]byte, 128), bytes.Repeat([]byte{255}, 128)} {
		if _, err := NewSignMasterPublicKey(raw); err == nil {
			t.Fatal("accepted malformed G2")
		}
		if _, err := NewEncryptMasterPublicKey(raw); err == nil {
			t.Fatal("accepted malformed G1")
		}
	}
	if _, err := GenerateSignMasterKey(failingReader{}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	if _, err := GenerateEncryptMasterKey(bytes.NewReader(make([]byte, 32*128))); err == nil {
		t.Fatal("unbounded/accepted zero RNG")
	}
	master, key := encryptionFixture(t)
	for _, uid := range [][]byte{nil, make([]byte, MaxIdentitySize+1)} {
		if _, err := master.Extract(uid); err == nil {
			t.Fatal("bad identity")
		}
	}
	for _, size := range []int{-1, 0, MaxKeySize + 1} {
		if _, _, err := Encapsulate(rand.Reader, master.Public(), []byte("Bob"), size); err == nil {
			t.Fatal("bad KEM size")
		}
		if _, err := Decapsulate(key, []byte("Bob"), make([]byte, 64), size); err == nil {
			t.Fatal("bad KEM size")
		}
	}
	if _, err := Sign(nil, nil, nil); err == nil {
		t.Fatal("nil sign key")
	}
	if err := Verify(nil, nil, nil, nil); err == nil {
		t.Fatal("nil verify key")
	}
	if _, err := Encrypt(nil, nil, []byte("Bob"), []byte("x")); err == nil {
		t.Fatal("nil public key")
	}
	if _, err := Decrypt(nil, nil, make([]byte, 97)); err == nil {
		t.Fatal("nil private key")
	}
	original, _ := master.MarshalBinary()
	saved := append([]byte(nil), original...)
	imported, err := NewEncryptMasterPrivateKey(original)
	if err != nil {
		t.Fatal(err)
	}
	original[0] ^= 255
	got, _ := imported.MarshalBinary()
	if !bytes.Equal(got, saved) {
		t.Fatal("master key aliases input")
	}
	got[0] ^= 255
	again, _ := imported.MarshalBinary()
	if !bytes.Equal(again, saved) {
		t.Fatal("master export aliases secret")
	}
	if _, err := Encrypt(nil, master.Public(), []byte("Bob"), nil); err == nil {
		t.Fatal("accepted empty message")
	}
}

func TestRejectNonCanonicalInfinity(t *testing.T) {
	modulus := unhex(t, "b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457d")
	malformed := append(append([]byte(nil), modulus...), modulus...)
	if _, err := NewEncryptMasterPublicKey(malformed); err == nil {
		t.Fatal("accepted (p,p) noncanonical infinity")
	}
	master, key := encryptionFixture(t)
	if _, err := Decapsulate(key, []byte("Bob"), malformed, 32); err == nil {
		t.Fatal("accepted (p,p) encapsulation")
	}
	ciphertext, err := Encrypt(nil, master.Public(), []byte("Bob"), []byte("message"))
	if err != nil {
		t.Fatal(err)
	}
	copy(ciphertext, malformed)
	if out, err := Decrypt(key, []byte("Bob"), ciphertext); err == nil || out != nil {
		t.Fatal("accepted noncanonical C1")
	}
	signer, err := GenerateSignMasterKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signature := append(scalarHex(t, "01"), malformed...)
	if Verify(signer.Public(), []byte("Alice"), []byte("message"), signature) == nil {
		t.Fatal("accepted noncanonical signature point")
	}
}

func TestCoordinateBoundsAndTrailingBytes(t *testing.T) {
	prime := unhex(t, "b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457d")
	sign, err := GenerateSignMasterKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	g2, _ := sign.Public().MarshalBinary()
	enc, _ := encryptionFixture(t)
	g1, _ := enc.Public().MarshalBinary()
	for i := 0; i < 2; i++ {
		for _, invalid := range [][]byte{prime, bytes.Repeat([]byte{255}, 32)} {
			bad := append([]byte(nil), g1...)
			copy(bad[i*32:], invalid)
			if _, err := NewEncryptMasterPublicKey(bad); err == nil {
				t.Fatalf("accepted G1 coordinate %d outside field", i)
			}
		}
	}
	for i := 0; i < 4; i++ {
		for _, invalid := range [][]byte{prime, bytes.Repeat([]byte{255}, 32)} {
			bad := append([]byte(nil), g2...)
			copy(bad[i*32:], invalid)
			if _, err := NewSignMasterPublicKey(bad); err == nil {
				t.Fatalf("accepted G2 coordinate %d outside field", i)
			}
		}
	}
	for _, bad := range [][]byte{g1[:63], append(g1, 0)} {
		if _, err := NewEncryptMasterPublicKey(bad); err == nil {
			t.Fatal("accepted nonexact G1 encoding")
		}
	}
	for _, bad := range [][]byte{g2[:127], append(g2, 0)} {
		if _, err := NewSignMasterPublicKey(bad); err == nil {
			t.Fatal("accepted nonexact G2 encoding")
		}
	}
}
