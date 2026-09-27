package sm9

import (
	"crypto/subtle"
	"errors"
	"io"

	"www.gitlablow.com/wave4y/cryptoutils/sm3"
	"www.gitlablow.com/wave4y/cryptoutils/sm4"
	"www.gitlablow.com/wave4y/cryptoutils/sm9/internal/bn256"
)

// Sign signs the supplied message directly (SM9 performs H2 internally).
// The signature is the fixed-width 32 byte h followed by the 64 byte G1 point S.
// A nil random source selects crypto/rand.Reader.
func Sign(random io.Reader, key *SignPrivateKey, message []byte) ([]byte, error) {
	if key == nil || key.point == nil || key.public == nil || key.public.point == nil {
		return nil, ErrKey
	}
	if len(message) > MaxMessageSize {
		return nil, ErrSize
	}
	g := bn256.Pair(bn256.Gen1, key.public.point)
	for attempt := 0; attempt < 128; attempt++ {
		r, err := randomScalar(random)
		if err != nil {
			return nil, err
		}
		w, err := bn256.ScalarMultGT(g, scalarBytes(r))
		if err != nil {
			return nil, err
		}
		h := hashToScalar(2, message, w.Marshal())
		r.Sub(r, h)
		r.Mod(r, bn256.Order)
		if r.Sign() == 0 {
			continue
		}
		s, err := new(bn256.G1).ScalarMult(key.point, scalarBytes(r))
		if err != nil {
			return nil, err
		}
		return append(scalarBytes(h), s.Marshal()...), nil
	}
	return nil, errors.New("sm9: signing nonce retry limit reached")
}

// Verify checks a raw SM9 signature for an exact byte-string identity (HID=1).
func Verify(pub *SignMasterPublicKey, uid, message, signature []byte) error {
	if pub == nil || pub.point == nil {
		return ErrKey
	}
	if err := validIdentity(uid); err != nil {
		return err
	}
	if len(message) > MaxMessageSize {
		return ErrSize
	}
	if len(signature) != SignatureSize {
		return ErrSignature
	}
	h, err := parseScalar(signature[:32])
	if err != nil {
		return ErrSignature
	}
	s, err := parseG1(signature[32:])
	if err != nil {
		return ErrSignature
	}
	q, err := new(bn256.G2).ScalarBaseMult(scalarBytes(h1(uid, 1)))
	if err != nil {
		return ErrSignature
	}
	q.Add(q, pub.point)
	if allZero(q.Marshal()) {
		return ErrSignature
	}
	g := bn256.Pair(bn256.Gen1, pub.point)
	t, err := bn256.ScalarMultGT(g, scalarBytes(h))
	if err != nil {
		return ErrSignature
	}
	w := new(bn256.GT).Add(bn256.Pair(s, q), t)
	expected := scalarBytes(hashToScalar(2, message, w.Marshal()))
	if subtle.ConstantTimeCompare(signature[:32], expected) != 1 {
		return ErrSignature
	}
	return nil
}

// Encapsulate generates a key and its 64 byte SM9 encapsulation (HID=3).
// Key size is measured in bytes, not bits. KEM alone does not authenticate data.
func Encapsulate(random io.Reader, pub *EncryptMasterPublicKey, uid []byte, size int) (key, encapsulation []byte, err error) {
	if size < 1 || size > MaxKeySize {
		return nil, nil, ErrSize
	}
	return encapsulate(random, pub, uid, size, size)
}
func encapsulate(random io.Reader, pub *EncryptMasterPublicKey, uid []byte, size, nonzero int) ([]byte, []byte, error) {
	if pub == nil || pub.point == nil {
		return nil, nil, ErrKey
	}
	if err := validIdentity(uid); err != nil {
		return nil, nil, err
	}
	q, err := new(bn256.G1).ScalarBaseMult(scalarBytes(h1(uid, 3)))
	if err != nil {
		return nil, nil, err
	}
	q.Add(q, pub.point)
	if allZero(q.Marshal()) {
		return nil, nil, ErrKey
	}
	g := bn256.Pair(pub.point, bn256.Gen2)
	for attempt := 0; attempt < 128; attempt++ {
		r, err := randomScalar(random)
		if err != nil {
			return nil, nil, err
		}
		c, err := new(bn256.G1).ScalarMult(q, scalarBytes(r))
		if err != nil {
			return nil, nil, err
		}
		w, err := bn256.ScalarMultGT(g, scalarBytes(r))
		if err != nil {
			return nil, nil, err
		}
		cBytes := c.Marshal()
		z := append(append(append([]byte(nil), cBytes...), w.Marshal()...), uid...)
		key := kdf(z, size)
		if allZero(key[:nonzero]) {
			continue
		}
		return key, cBytes, nil
	}
	return nil, nil, errors.New("sm9: encapsulation retry limit reached")
}

// Decapsulate derives the key for an SM9 encapsulation. The identity must match
// the identity attached to key. Unauthenticated KEM output must be used with an
// authenticated protocol; altered valid group points can produce different keys.
func Decapsulate(key *EncryptPrivateKey, uid, encapsulation []byte, size int) ([]byte, error) {
	if size < 1 || size > MaxKeySize {
		return nil, ErrSize
	}
	return decapsulate(key, uid, encapsulation, size, size)
}
func decapsulate(key *EncryptPrivateKey, uid, encoded []byte, size, nonzero int) ([]byte, error) {
	if key == nil || key.point == nil {
		return nil, ErrKey
	}
	if err := validIdentity(uid); err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(uid, key.identity) != 1 {
		return nil, ErrCiphertext
	}
	c, err := parseG1(encoded)
	if err != nil {
		return nil, ErrCiphertext
	}
	w := bn256.Pair(c, key.point)
	z := append(append(append([]byte(nil), encoded...), w.Marshal()...), uid...)
	derived := kdf(z, size)
	if allZero(derived[:nonzero]) {
		return nil, ErrCiphertext
	}
	return derived, nil
}

// EncryptionMode identifies the standard's stream or block cipher construction.
// Mode selection is external to the raw C1||C3||C2 encoding.
type EncryptionMode uint8

const (
	XOR    EncryptionMode = 0
	SM4ECB EncryptionMode = 1
)

// Encrypt uses SM9's XOR construction and returns C1(64)||C3(32)||C2.
// Empty plaintext is rejected. For block encryption use EncryptWithMode.
func Encrypt(random io.Reader, pub *EncryptMasterPublicKey, uid, plaintext []byte) ([]byte, error) {
	return EncryptWithMode(random, pub, uid, plaintext, XOR)
}
func EncryptWithMode(random io.Reader, pub *EncryptMasterPublicKey, uid, plaintext []byte, mode EncryptionMode) ([]byte, error) {
	if len(plaintext) == 0 || len(plaintext) > MaxMessageSize {
		return nil, ErrSize
	}
	k1Len := len(plaintext)
	switch mode {
	case XOR:
	case SM4ECB:
		k1Len = 16
	default:
		return nil, errors.New("sm9: unsupported encryption mode")
	}
	key, c1, err := encapsulate(random, pub, uid, k1Len+32, k1Len)
	if err != nil {
		return nil, err
	}
	var c2 []byte
	if mode == XOR {
		c2 = make([]byte, len(plaintext))
		for i, b := range plaintext {
			c2[i] = b ^ key[i]
		}
	} else {
		block, err := sm4.NewCipher(key[:16])
		if err != nil {
			return nil, err
		}
		pad := 16 - len(plaintext)%16
		c2 = make([]byte, len(plaintext)+pad)
		copy(c2, plaintext)
		for i := len(plaintext); i < len(c2); i++ {
			c2[i] = byte(pad)
		}
		for i := 0; i < len(c2); i += 16 {
			block.Encrypt(c2[i:i+16], c2[i:i+16])
		}
	}
	h := sm3.New()
	h.Write(c2)
	h.Write(key[k1Len:])
	tag := h.Sum(nil)
	out := make([]byte, 0, 64+32+len(c2))
	out = append(out, c1...)
	out = append(out, tag...)
	out = append(out, c2...)
	return out, nil
}

// Decrypt authenticates a raw XOR ciphertext before releasing plaintext.
func Decrypt(key *EncryptPrivateKey, uid, ciphertext []byte) ([]byte, error) {
	return DecryptWithMode(key, uid, ciphertext, XOR)
}
func DecryptWithMode(key *EncryptPrivateKey, uid, ciphertext []byte, mode EncryptionMode) ([]byte, error) {
	if len(ciphertext) <= 96 || len(ciphertext) > 96+MaxMessageSize+16 {
		return nil, ErrCiphertext
	}
	c2 := ciphertext[96:]
	k1Len := len(c2)
	switch mode {
	case XOR:
		if len(c2) > MaxMessageSize {
			return nil, ErrCiphertext
		}
	case SM4ECB:
		if len(c2)%16 != 0 {
			return nil, ErrCiphertext
		}
		k1Len = 16
	default:
		return nil, ErrCiphertext
	}
	derived, err := decapsulate(key, uid, ciphertext[:64], k1Len+32, k1Len)
	if err != nil {
		return nil, err
	}
	h := sm3.New()
	h.Write(c2)
	h.Write(derived[k1Len:])
	if subtle.ConstantTimeCompare(ciphertext[64:96], h.Sum(nil)) != 1 {
		return nil, ErrCiphertext
	}
	plaintext := make([]byte, len(c2))
	if mode == XOR {
		for i, b := range c2 {
			plaintext[i] = b ^ derived[i]
		}
		return plaintext, nil
	}
	block, err := sm4.NewCipher(derived[:16])
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(c2); i += 16 {
		block.Decrypt(plaintext[i:i+16], c2[i:i+16])
	}
	pad := int(plaintext[len(plaintext)-1])
	valid := subtle.ConstantTimeLessOrEq(1, pad) & subtle.ConstantTimeLessOrEq(pad, 16)
	for i := 1; i <= 16; i++ {
		valid &= subtle.ConstantTimeSelect(subtle.ConstantTimeLessOrEq(i, pad), subtle.ConstantTimeByteEq(plaintext[len(plaintext)-i], byte(pad)), 1)
	}
	if valid != 1 || len(plaintext)-pad == 0 || len(plaintext)-pad > MaxMessageSize {
		return nil, ErrCiphertext
	}
	return plaintext[:len(plaintext)-pad], nil
}
