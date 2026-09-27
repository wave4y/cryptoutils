package cryptoutils

import (
	"crypto/rand"
	"errors"
	"github.com/wave4y/cryptoutils/sm2"
)

type SM2PrivateKey = sm2.PrivateKey
type SM2PublicKey = sm2.PublicKey
type SM2ExchangeResult = sm2.ExchangeResult

func GenerateSM2Key() (*SM2PrivateKey, error)               { return sm2.GenerateKey(rand.Reader) }
func ParseSM2PrivateKey(raw []byte) (*SM2PrivateKey, error) { return sm2.NewPrivateKey(raw) }
func ParseSM2PublicKey(raw []byte) (*SM2PublicKey, error)   { return sm2.ParsePublicKey(raw) }
func EncryptSM2(data []byte, key *SM2PublicKey) ([]byte, error) {
	return sm2.Encrypt(rand.Reader, key, data)
}
func DecryptSM2(data []byte, key *SM2PrivateKey) ([]byte, error) { return sm2.Decrypt(key, data) }
func SignSM2(data, uid []byte, key *SM2PrivateKey) ([]byte, error) {
	return sm2.Sign(rand.Reader, key, uid, data)
}
func VerifySM2(data, uid, signature []byte, key *SM2PublicKey) error {
	if !sm2.Verify(key, uid, data, signature) {
		return errors.New("cryptoutils: SM2 signature verification failed")
	}
	return nil
}
func ExchangeSM2(key, ephemeral *SM2PrivateKey, peer, peerEphemeral *SM2PublicKey, uid, peerUID []byte, initiator bool, keyLen int) (*SM2ExchangeResult, error) {
	return sm2.Exchange(key, ephemeral, peer, peerEphemeral, uid, peerUID, initiator, keyLen)
}
func (p *CryptoData) SM2Encrypt(key *SM2PublicKey) *CryptoData {
	if p.err != nil {
		return p
	}
	out, err := EncryptSM2(p.data, key)
	if err != nil {
		return p.fail(err)
	}
	p.data = out
	return p
}
func (p *CryptoData) SM2Decrypt(key *SM2PrivateKey) *CryptoData {
	if p.err != nil {
		return p
	}
	out, err := DecryptSM2(p.data, key)
	if err != nil {
		return p.fail(err)
	}
	p.data = out
	return p
}
func (p *CryptoData) SM2Sign(key *SM2PrivateKey, uid []byte) *CryptoData {
	if p.err != nil {
		return p
	}
	out, err := SignSM2(p.data, uid, key)
	if err != nil {
		return p.fail(err)
	}
	p.data = out
	return p
}
func (p *CryptoData) SM2Verify(key *SM2PublicKey, uid, signature []byte) *CryptoData {
	if p.err != nil {
		return p
	}
	if err := VerifySM2(p.data, uid, signature, key); err != nil {
		return p.fail(err)
	}
	return p
}
