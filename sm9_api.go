package cryptoutils

import (
	"crypto/rand"
	"www.gitlablow.com/wave4y/cryptoutils/sm9"
)

// SM9 key types keep their scalar and curve-point representations private.
type SM9SignMasterPrivateKey = sm9.SignMasterPrivateKey
type SM9SignMasterPublicKey = sm9.SignMasterPublicKey
type SM9SignPrivateKey = sm9.SignPrivateKey
type SM9EncryptMasterPrivateKey = sm9.EncryptMasterPrivateKey
type SM9EncryptMasterPublicKey = sm9.EncryptMasterPublicKey
type SM9EncryptPrivateKey = sm9.EncryptPrivateKey
type SM9EncryptionMode = sm9.EncryptionMode

const (
	SM9XOR    SM9EncryptionMode = sm9.XOR
	SM9SM4ECB SM9EncryptionMode = sm9.SM4ECB
)

func GenerateSM9SignMasterKey() (*SM9SignMasterPrivateKey, error) {
	return sm9.GenerateSignMasterKey(rand.Reader)
}
func GenerateSM9EncryptMasterKey() (*SM9EncryptMasterPrivateKey, error) {
	return sm9.GenerateEncryptMasterKey(rand.Reader)
}
func ParseSM9SignMasterPrivateKey(raw []byte) (*SM9SignMasterPrivateKey, error) {
	return sm9.NewSignMasterPrivateKey(raw)
}
func ParseSM9EncryptMasterPrivateKey(raw []byte) (*SM9EncryptMasterPrivateKey, error) {
	return sm9.NewEncryptMasterPrivateKey(raw)
}
func ParseSM9SignMasterPublicKey(raw []byte) (*SM9SignMasterPublicKey, error) {
	return sm9.NewSignMasterPublicKey(raw)
}
func ParseSM9EncryptMasterPublicKey(raw []byte) (*SM9EncryptMasterPublicKey, error) {
	return sm9.NewEncryptMasterPublicKey(raw)
}
func ParseSM9SignPrivateKey(raw, identity []byte, master *SM9SignMasterPublicKey) (*SM9SignPrivateKey, error) {
	return sm9.NewSignPrivateKey(raw, identity, master)
}
func ParseSM9EncryptPrivateKey(raw, identity []byte, master *SM9EncryptMasterPublicKey) (*SM9EncryptPrivateKey, error) {
	return sm9.NewEncryptPrivateKey(raw, identity, master)
}

// SignSM9 signs message bytes directly; its result is h(32)||S(64), not hex.
func SignSM9(message []byte, key *SM9SignPrivateKey) ([]byte, error) {
	return sm9.Sign(rand.Reader, key, message)
}

// VerifySM9 authenticates the message under the exact identity and master key.
func VerifySM9(message, identity, signature []byte, master *SM9SignMasterPublicKey) error {
	return sm9.Verify(master, identity, message, signature)
}

// EncryptSM9 returns the standard XOR construction C1(64)||C3(32)||C2.
func EncryptSM9(plaintext, identity []byte, master *SM9EncryptMasterPublicKey) ([]byte, error) {
	return sm9.Encrypt(rand.Reader, master, identity, plaintext)
}
func DecryptSM9(ciphertext, identity []byte, key *SM9EncryptPrivateKey) ([]byte, error) {
	return sm9.Decrypt(key, identity, ciphertext)
}
func EncryptSM9WithMode(plaintext, identity []byte, master *SM9EncryptMasterPublicKey, mode SM9EncryptionMode) ([]byte, error) {
	return sm9.EncryptWithMode(rand.Reader, master, identity, plaintext, mode)
}
func DecryptSM9WithMode(ciphertext, identity []byte, key *SM9EncryptPrivateKey, mode SM9EncryptionMode) ([]byte, error) {
	return sm9.DecryptWithMode(key, identity, ciphertext, mode)
}

// EncapsulateSM9 returns the public encapsulation first and the shared secret second.
func EncapsulateSM9(identity []byte, master *SM9EncryptMasterPublicKey, keySize int) (encapsulation, sharedSecret []byte, err error) {
	sharedSecret, encapsulation, err = sm9.Encapsulate(rand.Reader, master, identity, keySize)
	return
}
func DecapsulateSM9(encapsulation, identity []byte, key *SM9EncryptPrivateKey, keySize int) ([]byte, error) {
	return sm9.Decapsulate(key, identity, encapsulation, keySize)
}

func (p *CryptoData) SM9Sign(key *SM9SignPrivateKey) *CryptoData {
	if p.err != nil {
		return p
	}
	data, err := SignSM9(p.data, key)
	if err != nil {
		return p.fail(err)
	}
	p.data = data
	return p
}

// SM9Verify keeps the message unchanged on success and records a sticky error on failure.
func (p *CryptoData) SM9Verify(master *SM9SignMasterPublicKey, identity, signature []byte) *CryptoData {
	if p.err != nil {
		return p
	}
	if err := VerifySM9(p.data, identity, signature, master); err != nil {
		return p.fail(err)
	}
	return p
}
func (p *CryptoData) SM9Encrypt(master *SM9EncryptMasterPublicKey, identity []byte) *CryptoData {
	if p.err != nil {
		return p
	}
	data, err := EncryptSM9(p.data, identity, master)
	if err != nil {
		return p.fail(err)
	}
	p.data = data
	return p
}
func (p *CryptoData) SM9Decrypt(key *SM9EncryptPrivateKey, identity []byte) *CryptoData {
	if p.err != nil {
		return p
	}
	data, err := DecryptSM9(p.data, identity, key)
	if err != nil {
		return p.fail(err)
	}
	p.data = data
	return p
}
func (p *CryptoData) SM9EncryptWithMode(master *SM9EncryptMasterPublicKey, identity []byte, mode SM9EncryptionMode) *CryptoData {
	if p.err != nil {
		return p
	}
	data, err := EncryptSM9WithMode(p.data, identity, master, mode)
	if err != nil {
		return p.fail(err)
	}
	p.data = data
	return p
}
func (p *CryptoData) SM9DecryptWithMode(key *SM9EncryptPrivateKey, identity []byte, mode SM9EncryptionMode) *CryptoData {
	if p.err != nil {
		return p
	}
	data, err := DecryptSM9WithMode(p.data, identity, key, mode)
	if err != nil {
		return p.fail(err)
	}
	p.data = data
	return p
}
