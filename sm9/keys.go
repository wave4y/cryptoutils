// Package sm9 implements the fixed-parameter SM9 identity-based signature,
// key encapsulation, and encryption schemes in GB/T 38635.2-2020.
// Keys are immutable after construction. See docs/sm9.md for wire formats,
// identity handling, implementation provenance, and timing limitations.
package sm9

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"math/big"

	"github.com/wave4y/cryptoutils/sm3"
	"github.com/wave4y/cryptoutils/sm9/internal/bn256"
)

const (
	MaxIdentitySize   = 65535
	MaxMessageSize    = 16 << 20
	MaxKeySize        = 1 << 20
	SignatureSize     = 96
	EncapsulationSize = 64
)

var (
	ErrKey        = errors.New("sm9: invalid key")
	ErrIdentity   = errors.New("sm9: identity must contain 1..65535 bytes")
	ErrSignature  = errors.New("sm9: invalid signature")
	ErrCiphertext = errors.New("sm9: invalid ciphertext")
	ErrSize       = errors.New("sm9: input or output exceeds the supported size")
	orderMinusOne = new(big.Int).Sub(new(big.Int).Set(bn256.Order), big.NewInt(1))
)

func validIdentity(uid []byte) error {
	if len(uid) == 0 || len(uid) > MaxIdentitySize {
		return ErrIdentity
	}
	return nil
}
func scalarBytes(n *big.Int) []byte { out := make([]byte, 32); return n.FillBytes(out) }
func parseScalar(raw []byte) (*big.Int, error) {
	if len(raw) != 32 {
		return nil, ErrKey
	}
	n := new(big.Int).SetBytes(raw)
	if n.Sign() == 0 || n.Cmp(bn256.Order) >= 0 {
		return nil, ErrKey
	}
	return n, nil
}
func randomScalar(random io.Reader) (*big.Int, error) {
	if random == nil {
		random = rand.Reader
	}
	var raw [32]byte
	for attempt := 0; attempt < 128; attempt++ {
		if _, err := io.ReadFull(random, raw[:]); err != nil {
			return nil, err
		}
		if n, err := parseScalar(raw[:]); err == nil {
			return n, nil
		}
	}
	return nil, errors.New("sm9: random source did not produce a valid scalar")
}
func hashToScalar(mode byte, parts ...[]byte) *big.Int {
	var digest [64]byte
	for ct := uint32(1); ct <= 2; ct++ {
		h := sm3.New()
		h.Write([]byte{mode})
		for _, p := range parts {
			h.Write(p)
		}
		var counter [4]byte
		binary.BigEndian.PutUint32(counter[:], ct)
		h.Write(counter[:])
		copy(digest[(ct-1)*32:], h.Sum(nil))
	}
	n := new(big.Int).SetBytes(digest[:40])
	n.Mod(n, orderMinusOne)
	return n.Add(n, big.NewInt(1))
}
func h1(uid []byte, hid byte) *big.Int { return hashToScalar(1, uid, []byte{hid}) }
func kdf(z []byte, size int) []byte {
	out := make([]byte, size)
	for pos, ct := 0, uint32(1); pos < size; ct++ {
		h := sm3.New()
		h.Write(z)
		var count [4]byte
		binary.BigEndian.PutUint32(count[:], ct)
		h.Write(count[:])
		pos += copy(out[pos:], h.Sum(nil))
	}
	return out
}
func allZero(data []byte) bool {
	var v byte
	for _, b := range data {
		v |= b
	}
	return subtle.ConstantTimeByteEq(v, 0) == 1
}
func parseG1(raw []byte) (*bn256.G1, error) {
	if len(raw) != 64 || allZero(raw) {
		return nil, ErrKey
	}
	p := new(bn256.G1)
	if rest, err := p.Unmarshal(raw); err != nil || len(rest) != 0 {
		return nil, ErrKey
	}
	canonical := p.Marshal()
	if allZero(canonical) || subtle.ConstantTimeCompare(raw, canonical) != 1 {
		return nil, ErrKey
	}
	// Validate subgroup membership independently of the point decoder.
	multiple, err := new(bn256.G1).ScalarMult(p, bn256.Order.Bytes())
	if err != nil || !allZero(multiple.Marshal()) {
		return nil, ErrKey
	}
	return p, nil
}
func parseG2(raw []byte) (*bn256.G2, error) {
	if len(raw) != 128 || allZero(raw) {
		return nil, ErrKey
	}
	p := new(bn256.G2)
	if rest, err := p.Unmarshal(raw); err != nil || len(rest) != 0 {
		return nil, ErrKey
	}
	canonical := p.Marshal()
	if allZero(canonical) || subtle.ConstantTimeCompare(raw, canonical) != 1 {
		return nil, ErrKey
	}
	multiple, err := new(bn256.G2).ScalarMult(p, bn256.Order.Bytes())
	if err != nil || !allZero(multiple.Marshal()) {
		return nil, ErrKey
	}
	return p, nil
}
func deriveScalar(master *big.Int, uid []byte, hid byte) (*big.Int, error) {
	t := h1(uid, hid)
	t.Add(t, master)
	t.Mod(t, bn256.Order)
	if t.Sign() == 0 {
		return nil, errors.New("sm9: identity requires a new master key")
	}
	t.ModInverse(t, bn256.Order)
	t.Mul(t, master)
	t.Mod(t, bn256.Order)
	return t, nil
}

// SignMasterPrivateKey is the KGC master secret for HID=0x01 signatures.
type SignMasterPrivateKey struct {
	scalar *big.Int
	public *SignMasterPublicKey
}
type SignMasterPublicKey struct{ point *bn256.G2 }
type SignPrivateKey struct {
	point    *bn256.G1
	public   *SignMasterPublicKey
	identity []byte
}

// EncryptMasterPrivateKey is the KGC master secret for HID=0x03 encryption/KEM.
type EncryptMasterPrivateKey struct {
	scalar *big.Int
	public *EncryptMasterPublicKey
}
type EncryptMasterPublicKey struct{ point *bn256.G1 }
type EncryptPrivateKey struct {
	point    *bn256.G2
	identity []byte
}

func GenerateSignMasterKey(random io.Reader) (*SignMasterPrivateKey, error) {
	n, err := randomScalar(random)
	if err != nil {
		return nil, err
	}
	return NewSignMasterPrivateKey(scalarBytes(n))
}
func GenerateEncryptMasterKey(random io.Reader) (*EncryptMasterPrivateKey, error) {
	n, err := randomScalar(random)
	if err != nil {
		return nil, err
	}
	return NewEncryptMasterPrivateKey(scalarBytes(n))
}
func NewSignMasterPrivateKey(raw []byte) (*SignMasterPrivateKey, error) {
	n, err := parseScalar(raw)
	if err != nil {
		return nil, err
	}
	point, err := new(bn256.G2).ScalarBaseMult(scalarBytes(n))
	if err != nil {
		return nil, err
	}
	return &SignMasterPrivateKey{n, &SignMasterPublicKey{point}}, nil
}
func NewEncryptMasterPrivateKey(raw []byte) (*EncryptMasterPrivateKey, error) {
	n, err := parseScalar(raw)
	if err != nil {
		return nil, err
	}
	point, err := new(bn256.G1).ScalarBaseMult(scalarBytes(n))
	if err != nil {
		return nil, err
	}
	return &EncryptMasterPrivateKey{n, &EncryptMasterPublicKey{point}}, nil
}
func NewSignMasterPublicKey(raw []byte) (*SignMasterPublicKey, error) {
	p, err := parseG2(raw)
	if err != nil {
		return nil, err
	}
	return &SignMasterPublicKey{p}, nil
}
func NewEncryptMasterPublicKey(raw []byte) (*EncryptMasterPublicKey, error) {
	p, err := parseG1(raw)
	if err != nil {
		return nil, err
	}
	return &EncryptMasterPublicKey{p}, nil
}
func (k *SignMasterPrivateKey) Public() *SignMasterPublicKey {
	if k == nil {
		return nil
	}
	return k.public
}
func (k *EncryptMasterPrivateKey) Public() *EncryptMasterPublicKey {
	if k == nil {
		return nil
	}
	return k.public
}
func (k *SignMasterPrivateKey) Extract(uid []byte) (*SignPrivateKey, error) {
	if k == nil || k.scalar == nil || k.public == nil {
		return nil, ErrKey
	}
	if err := validIdentity(uid); err != nil {
		return nil, err
	}
	scalar, err := deriveScalar(k.scalar, uid, 1)
	if err != nil {
		return nil, err
	}
	p, err := new(bn256.G1).ScalarBaseMult(scalarBytes(scalar))
	if err != nil {
		return nil, err
	}
	return &SignPrivateKey{p, k.public, append([]byte(nil), uid...)}, nil
}
func (k *EncryptMasterPrivateKey) Extract(uid []byte) (*EncryptPrivateKey, error) {
	if k == nil || k.scalar == nil || k.public == nil {
		return nil, ErrKey
	}
	if err := validIdentity(uid); err != nil {
		return nil, err
	}
	scalar, err := deriveScalar(k.scalar, uid, 3)
	if err != nil {
		return nil, err
	}
	p, err := new(bn256.G2).ScalarBaseMult(scalarBytes(scalar))
	if err != nil {
		return nil, err
	}
	return &EncryptPrivateKey{p, append([]byte(nil), uid...)}, nil
}
func (k *SignMasterPrivateKey) MarshalBinary() ([]byte, error) {
	if k == nil || k.scalar == nil {
		return nil, ErrKey
	}
	return scalarBytes(k.scalar), nil
}
func (k *EncryptMasterPrivateKey) MarshalBinary() ([]byte, error) {
	if k == nil || k.scalar == nil {
		return nil, ErrKey
	}
	return scalarBytes(k.scalar), nil
}
func (k *SignMasterPublicKey) MarshalBinary() ([]byte, error) {
	if k == nil || k.point == nil {
		return nil, ErrKey
	}
	return new(bn256.G2).Set(k.point).Marshal(), nil
}
func (k *EncryptMasterPublicKey) MarshalBinary() ([]byte, error) {
	if k == nil || k.point == nil {
		return nil, ErrKey
	}
	return new(bn256.G1).Set(k.point).Marshal(), nil
}
func (k *SignPrivateKey) MarshalBinary() ([]byte, error) {
	if k == nil || k.point == nil {
		return nil, ErrKey
	}
	return new(bn256.G1).Set(k.point).Marshal(), nil
}
func (k *EncryptPrivateKey) MarshalBinary() ([]byte, error) {
	if k == nil || k.point == nil {
		return nil, ErrKey
	}
	return new(bn256.G2).Set(k.point).Marshal(), nil
}

// NewSignPrivateKey imports a raw user key, checking its master public key and identity.
func NewSignPrivateKey(raw, uid []byte, pub *SignMasterPublicKey) (*SignPrivateKey, error) {
	if pub == nil || pub.point == nil {
		return nil, ErrKey
	}
	if err := validIdentity(uid); err != nil {
		return nil, err
	}
	p, err := parseG1(raw)
	if err != nil {
		return nil, err
	}
	q, err := new(bn256.G2).ScalarBaseMult(scalarBytes(h1(uid, 1)))
	if err != nil {
		return nil, err
	}
	q.Add(q, pub.point)
	if allZero(q.Marshal()) || subtle.ConstantTimeCompare(bn256.Pair(p, q).Marshal(), bn256.Pair(bn256.Gen1, pub.point).Marshal()) != 1 {
		return nil, ErrKey
	}
	return &SignPrivateKey{p, pub, append([]byte(nil), uid...)}, nil
}

// NewEncryptPrivateKey imports a raw user key, checking its master public key and identity.
func NewEncryptPrivateKey(raw, uid []byte, pub *EncryptMasterPublicKey) (*EncryptPrivateKey, error) {
	if pub == nil || pub.point == nil {
		return nil, ErrKey
	}
	if err := validIdentity(uid); err != nil {
		return nil, err
	}
	p, err := parseG2(raw)
	if err != nil {
		return nil, err
	}
	q, err := new(bn256.G1).ScalarBaseMult(scalarBytes(h1(uid, 3)))
	if err != nil {
		return nil, err
	}
	q.Add(q, pub.point)
	if allZero(q.Marshal()) || subtle.ConstantTimeCompare(bn256.Pair(q, p).Marshal(), bn256.Pair(pub.point, bn256.Gen2).Marshal()) != 1 {
		return nil, ErrKey
	}
	return &EncryptPrivateKey{p, append([]byte(nil), uid...)}, nil
}
