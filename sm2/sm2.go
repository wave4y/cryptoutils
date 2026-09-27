// Package sm2 implements the prime-field SM2 algorithms in GB/T 32918.
// This portable big.Int implementation is intended for interoperability and
// testing; secret-key operations are not guaranteed to run in constant time.
package sm2

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"io"
	"math/big"

	"www.gitlablow.com/wave4y/cryptoutils/sm3"
)

var curve = makeCurve()
var defaultID = []byte("1234567812345678")
var errKey = errors.New("sm2: invalid key")
var errCiphertext = errors.New("sm2: invalid ciphertext")

func integer(s string) *big.Int {
	x, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("sm2: invalid curve constant")
	}
	return x
}
func makeCurve() *elliptic.CurveParams {
	return &elliptic.CurveParams{
		P:  integer("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"),
		N:  integer("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"),
		B:  integer("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"),
		Gx: integer("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"),
		Gy: integer("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"), BitSize: 256, Name: "SM2-P-256"}
}

// PublicKey holds an SM2 point. Use ParsePublicKey for untrusted encodings.
type PublicKey struct{ X, Y *big.Int }

// PrivateKey contains a scalar and its corresponding public point.
type PrivateKey struct {
	PublicKey
	D *big.Int
}

func validPublic(p *PublicKey) bool {
	return p != nil && p.X != nil && p.Y != nil && p.X.Sign() >= 0 && p.Y.Sign() >= 0 && p.X.Cmp(curve.P) < 0 && p.Y.Cmp(curve.P) < 0 && curve.IsOnCurve(p.X, p.Y)
}
func validPrivate(p *PrivateKey) bool {
	if p == nil || p.D == nil || p.D.Sign() <= 0 || p.D.Cmp(new(big.Int).Sub(curve.N, big.NewInt(1))) >= 0 || !validPublic(&p.PublicKey) {
		return false
	}
	x, y := curve.ScalarBaseMult(p.D.Bytes())
	return x.Cmp(p.X) == 0 && y.Cmp(p.Y) == 0
}
func fixed(x *big.Int) []byte { out := make([]byte, 32); x.FillBytes(out); return out }

// GenerateKey reads uniform secret scalars from random; nil selects crypto/rand.
func GenerateKey(random io.Reader) (*PrivateKey, error) {
	if random == nil {
		random = rand.Reader
	}
	n := new(big.Int).Sub(curve.N, big.NewInt(2))
	d, e := rand.Int(random, n)
	if e != nil {
		return nil, e
	}
	d.Add(d, big.NewInt(1))
	return NewPrivateKey(fixed(d))
}

// NewPrivateKey parses a 32-byte big-endian scalar in [1,n-2].
func NewPrivateKey(raw []byte) (*PrivateKey, error) {
	if len(raw) != 32 {
		return nil, errKey
	}
	d := new(big.Int).SetBytes(raw)
	if d.Sign() <= 0 || d.Cmp(new(big.Int).Sub(curve.N, big.NewInt(1))) >= 0 {
		return nil, errKey
	}
	x, y := curve.ScalarBaseMult(raw)
	return &PrivateKey{PublicKey{x, y}, d}, nil
}
func (p *PrivateKey) Bytes() ([]byte, error) {
	if !validPrivate(p) {
		return nil, errKey
	}
	return fixed(p.D), nil
}

// Bytes returns the SEC1 uncompressed 65-byte encoding.
func (p *PublicKey) Bytes() ([]byte, error) {
	if !validPublic(p) {
		return nil, errKey
	}
	return elliptic.Marshal(curve, p.X, p.Y), nil
}
func ParsePublicKey(raw []byte) (*PublicKey, error) {
	if len(raw) != 65 || raw[0] != 4 {
		return nil, errKey
	}
	x, y := elliptic.Unmarshal(curve, raw)
	p := &PublicKey{x, y}
	if !validPublic(p) {
		return nil, errKey
	}
	return p, nil
}

// ZA returns the SM2 identity binding digest. nil uid selects the conventional
// 16-byte default ID; an explicitly empty slice means an empty ID.
func ZA(pub *PublicKey, uid []byte) ([]byte, error) {
	if !validPublic(pub) {
		return nil, errKey
	}
	if uid == nil {
		uid = defaultID
	}
	if len(uid) > 8191 {
		return nil, errors.New("sm2: identity exceeds 65535 bits")
	}
	h := sm3.New()
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(uid)*8))
	h.Write(size[:])
	h.Write(uid)
	a := new(big.Int).Sub(curve.P, big.NewInt(3))
	for _, v := range []*big.Int{a, curve.B, curve.Gx, curve.Gy, pub.X, pub.Y} {
		h.Write(fixed(v))
	}
	return h.Sum(nil), nil
}
func digest(pub *PublicKey, uid, msg []byte) ([]byte, error) {
	z, e := ZA(pub, uid)
	if e != nil {
		return nil, e
	}
	h := sm3.New()
	h.Write(z)
	h.Write(msg)
	return h.Sum(nil), nil
}

type signature struct{ R, S *big.Int }

// Sign returns ASN.1 DER (r,s), hashing ZA||message with SM3.
func Sign(random io.Reader, priv *PrivateKey, uid, message []byte) ([]byte, error) {
	if !validPrivate(priv) {
		return nil, errKey
	}
	hash, e := digest(&priv.PublicKey, uid, message)
	if e != nil {
		return nil, e
	}
	if random == nil {
		random = rand.Reader
	}
	one := big.NewInt(1)
	inverse := new(big.Int).ModInverse(new(big.Int).Add(priv.D, one), curve.N)
	limit := new(big.Int).Sub(curve.N, one)
	for attempts := 0; attempts < 128; attempts++ {
		k, e := rand.Int(random, limit)
		if e != nil {
			return nil, e
		}
		k.Add(k, one)
		x, _ := curve.ScalarBaseMult(k.Bytes())
		r := new(big.Int).Add(new(big.Int).SetBytes(hash), x)
		r.Mod(r, curve.N)
		if r.Sign() == 0 || new(big.Int).Add(r, k).Cmp(curve.N) == 0 {
			continue
		}
		s := new(big.Int).Mul(r, priv.D)
		s.Sub(k, s)
		s.Mul(s, inverse)
		s.Mod(s, curve.N)
		if s.Sign() != 0 {
			return asn1.Marshal(signature{r, s})
		}
	}
	return nil, errors.New("sm2: random source failed to produce a signature")
}
func Verify(pub *PublicKey, uid, message, sig []byte) bool {
	hash, err := digest(pub, uid, message)
	return err == nil && VerifyDigest(pub, hash, sig)
}
func kdf(z []byte, n int) ([]byte, error) {
	if n < 1 || n > 16<<20 {
		return nil, errors.New("sm2: KDF length must be 1..16777216 bytes")
	}
	out := make([]byte, n)
	var count [4]byte
	for i := 0; i < n; i += 32 {
		binary.BigEndian.PutUint32(count[:], uint32(i/32+1))
		h := sm3.New()
		h.Write(z)
		h.Write(count[:])
		copy(out[i:], h.Sum(nil))
	}
	return out, nil
}
func allZero(v []byte) bool {
	var x byte
	for _, b := range v {
		x |= b
	}
	return x == 0
}

// Encrypt returns 04||C1.x||C1.y||C3||C2. Empty plaintext is rejected.
func Encrypt(random io.Reader, pub *PublicKey, message []byte) ([]byte, error) {
	if !validPublic(pub) {
		return nil, errKey
	}
	if len(message) == 0 || len(message) > 16<<20 {
		return nil, errors.New("sm2: plaintext length must be 1..16777216 bytes")
	}
	if random == nil {
		random = rand.Reader
	}
	limit := new(big.Int).Sub(curve.N, big.NewInt(1))
	for attempts := 0; attempts < 128; attempts++ {
		k, e := rand.Int(random, limit)
		if e != nil {
			return nil, e
		}
		k.Add(k, big.NewInt(1))
		c1x, c1y := curve.ScalarBaseMult(k.Bytes())
		x, y := curve.ScalarMult(pub.X, pub.Y, k.Bytes())
		xb, yb := fixed(x), fixed(y)
		mask, _ := kdf(append(xb, yb...), len(message))
		if allZero(mask) {
			continue
		}
		for i := range mask {
			mask[i] ^= message[i]
		}
		h := sm3.New()
		h.Write(xb)
		h.Write(message)
		h.Write(yb)
		out := elliptic.Marshal(curve, c1x, c1y)
		out = append(out, h.Sum(nil)...)
		return append(out, mask...), nil
	}
	return nil, errors.New("sm2: random source failed")
}
func Decrypt(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	if !validPrivate(priv) {
		return nil, errKey
	}
	if len(ciphertext) < 98 || len(ciphertext) > 97+(16<<20) {
		return nil, errCiphertext
	}
	c1, e := ParsePublicKey(ciphertext[:65])
	if e != nil {
		return nil, errCiphertext
	}
	x, y := curve.ScalarMult(c1.X, c1.Y, priv.D.Bytes())
	xb, yb := fixed(x), fixed(y)
	plain, _ := kdf(append(xb, yb...), len(ciphertext)-97)
	if allZero(plain) {
		return nil, errCiphertext
	}
	for i := range plain {
		plain[i] ^= ciphertext[97+i]
	}
	h := sm3.New()
	h.Write(xb)
	h.Write(plain)
	h.Write(yb)
	if subtle.ConstantTimeCompare(h.Sum(nil), ciphertext[65:97]) != 1 {
		for i := range plain {
			plain[i] = 0
		}
		return nil, errCiphertext
	}
	return plain, nil
}

// ExchangeResult withholds the shared key until the peer's confirmation passes.
type ExchangeResult struct{ key, send, expected []byte }

func (r *ExchangeResult) Confirmation() []byte {
	if r == nil {
		return nil
	}
	return append([]byte{}, r.send...)
}
func (r *ExchangeResult) Confirm(peerTag []byte) ([]byte, error) {
	if r == nil || len(r.expected) != 32 || subtle.ConstantTimeCompare(peerTag, r.expected) != 1 {
		return nil, errors.New("sm2: key confirmation failed")
	}
	return append([]byte{}, r.key...), nil
}

// Exchange implements GB/T 32918.3 with static and single-use ephemeral keys.
// Both parties use their own uid first; initiator determines the canonical A/B order.
// Send Confirmation() and require Confirm(peerTag) before using the shared key.
func Exchange(priv, eph *PrivateKey, peer, peerEph *PublicKey, uid, peerUID []byte, initiator bool, keyLen int) (*ExchangeResult, error) {
	if !validPrivate(priv) || !validPrivate(eph) || !validPublic(peer) || !validPublic(peerEph) {
		return nil, errKey
	}
	if keyLen < 1 || keyLen > 65536 {
		return nil, errors.New("sm2: exchange key length must be 1..65536")
	}
	if priv.D.Cmp(eph.D) == 0 {
		return nil, errors.New("sm2: static and ephemeral keys must differ")
	}
	za, e := ZA(&priv.PublicKey, uid)
	if e != nil {
		return nil, e
	}
	zb, e := ZA(peer, peerUID)
	if e != nil {
		return nil, e
	}
	xbar := func(x *big.Int) *big.Int {
		v := new(big.Int).Lsh(big.NewInt(1), 127)
		mask := new(big.Int).Sub(v, big.NewInt(1))
		return new(big.Int).Add(v, new(big.Int).And(x, mask))
	}
	t := new(big.Int).Mul(xbar(eph.X), eph.D)
	t.Add(t, priv.D)
	t.Mod(t, curve.N)
	if t.Sign() == 0 {
		return nil, errKey
	}
	qx, qy := curve.ScalarMult(peerEph.X, peerEph.Y, xbar(peerEph.X).Bytes())
	qx, qy = curve.Add(peer.X, peer.Y, qx, qy)
	if qx.Sign() == 0 && qy.Sign() == 0 {
		return nil, errKey
	}
	x, y := curve.ScalarMult(qx, qy, t.Bytes())
	if x.Sign() == 0 && y.Sign() == 0 {
		return nil, errKey
	}
	ra, rb := &eph.PublicKey, peerEph
	if !initiator {
		za, zb = zb, za
		ra, rb = rb, ra
	}
	z := append(fixed(x), fixed(y)...)
	z = append(z, za...)
	z = append(z, zb...)
	key, _ := kdf(z, keyLen)
	if allZero(key) {
		return nil, errors.New("sm2: zero exchange key; retry with new ephemeral keys")
	}
	h := sm3.New()
	h.Write(fixed(x))
	h.Write(za)
	h.Write(zb)
	h.Write(fixed(ra.X))
	h.Write(fixed(ra.Y))
	h.Write(fixed(rb.X))
	h.Write(fixed(rb.Y))
	inner := h.Sum(nil)
	confirmation := func(prefix byte) []byte {
		h := sm3.New()
		h.Write([]byte{prefix})
		h.Write(fixed(y))
		h.Write(inner)
		return h.Sum(nil)
	}
	s1, s2 := confirmation(2), confirmation(3)
	if initiator {
		return &ExchangeResult{key, s2, s1}, nil
	}
	return &ExchangeResult{key, s1, s2}, nil
}

// VerifyDigest verifies an ASN.1 signature against an already-computed 32-byte
// SM2 digest. Prefer Verify, which performs the identity binding itself.
func VerifyDigest(pub *PublicKey, hash, sig []byte) bool {
	if len(hash) != 32 || len(sig) < 8 || len(sig) > 72 || !validPublic(pub) {
		return false
	}
	var rs signature
	rest, e := asn1.Unmarshal(sig, &rs)
	if e != nil || len(rest) != 0 || rs.R == nil || rs.S == nil || rs.R.Sign() <= 0 || rs.S.Sign() <= 0 || rs.R.Cmp(curve.N) >= 0 || rs.S.Cmp(curve.N) >= 0 {
		return false
	}
	canonical, e := asn1.Marshal(rs)
	if e != nil || !bytes.Equal(canonical, sig) {
		return false
	}
	t := new(big.Int).Add(rs.R, rs.S)
	t.Mod(t, curve.N)
	if t.Sign() == 0 {
		return false
	}
	x1, y1 := curve.ScalarBaseMult(rs.S.Bytes())
	x2, y2 := curve.ScalarMult(pub.X, pub.Y, t.Bytes())
	x, y := curve.Add(x1, y1, x2, y2)
	if x.Sign() == 0 && y.Sign() == 0 {
		return false
	}
	r := new(big.Int).Add(new(big.Int).SetBytes(hash), x)
	r.Mod(r, curve.N)
	return r.Cmp(rs.R) == 0
}

type asn1Ciphertext struct {
	X, Y             *big.Int
	Hash, Ciphertext []byte
}

// EncryptASN1 uses the interoperable DER sequence (x,y,C3,C2).
func EncryptASN1(random io.Reader, pub *PublicKey, message []byte) ([]byte, error) {
	raw, e := Encrypt(random, pub, message)
	if e != nil {
		return nil, e
	}
	return asn1.Marshal(asn1Ciphertext{new(big.Int).SetBytes(raw[1:33]), new(big.Int).SetBytes(raw[33:65]), raw[65:97], raw[97:]})
}

// DecryptASN1 strictly parses the DER ciphertext, rejecting trailing data.
func DecryptASN1(priv *PrivateKey, data []byte) ([]byte, error) {
	if len(data) > (16<<20)+256 {
		return nil, errCiphertext
	}
	var c asn1Ciphertext
	rest, e := asn1.Unmarshal(data, &c)
	if e != nil || len(rest) != 0 || !validPublic(&PublicKey{c.X, c.Y}) || len(c.Hash) != 32 {
		return nil, errCiphertext
	}
	canonical, e := asn1.Marshal(c)
	if e != nil || !bytes.Equal(canonical, data) {
		return nil, errCiphertext
	}
	raw := elliptic.Marshal(curve, c.X, c.Y)
	raw = append(raw, c.Hash...)
	raw = append(raw, c.Ciphertext...)
	return Decrypt(priv, raw)
}
