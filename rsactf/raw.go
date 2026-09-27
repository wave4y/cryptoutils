// Package rsactf provides integer primitives for textbook RSA and CTF analysis.
// It accepts small moduli and arbitrary-size exponents. These variable-time,
// unpadded operations are not substitutes for authenticated or padded encryption.
// All functions preserve their input big.Int values.
package rsactf

import "math/big"

func validModulus(n *big.Int) bool { return n != nil && n.Cmp(big.NewInt(1)) > 0 }
func validResidue(x, n *big.Int) bool {
	return validModulus(n) && x != nil && x.Sign() >= 0 && x.Cmp(n) < 0
}
func validExponent(e *big.Int) bool { return e != nil && e.Sign() > 0 }

// EncryptRaw computes m^e mod n without padding. It requires n > 1, e > 0,
// and 0 <= m < n. It does not require prime factors or restrict the size of e.
func EncryptRaw(n, e, m *big.Int) (*big.Int, error) {
	if !validModulus(n) || !validExponent(e) || !validResidue(m, n) {
		return nil, ErrInvalidInput
	}
	return new(big.Int).Exp(m, e, n), nil
}

// DecryptRaw computes c^d mod n without padding or a public exponent. It requires
// n > 1, d > 0 and 0 <= c < n. The caller must establish that d is appropriate;
// success only indicates the modular exponentiation was performed.
func DecryptRaw(n, d, c *big.Int) (*big.Int, error) {
	if !validModulus(n) || !validExponent(d) || !validResidue(c, n) {
		return nil, ErrInvalidInput
	}
	return new(big.Int).Exp(c, d, n), nil
}

// DecryptCRT combines c^dp mod p and c^dq mod q for distinct odd probable primes.
// It requires 0 < dp < p-1, 0 < dq < q-1, and 0 <= c < p*q. No e or d is needed.
// Without e this function cannot confirm that supplied CRT exponents are valid.
// It rejects p=q; use DecryptRaw with the correct exponent for that case.
func DecryptCRT(p, q, dp, dq, c *big.Int) (*big.Int, error) {
	if !validModulus(p) || !validModulus(q) || p.Cmp(q) == 0 || !validExponent(dp) || !validExponent(dq) {
		return nil, ErrInvalidInput
	}
	one := big.NewInt(1)
	if dp.Cmp(new(big.Int).Sub(p, one)) >= 0 || dq.Cmp(new(big.Int).Sub(q, one)) >= 0 {
		return nil, ErrInvalidInput
	}
	n := new(big.Int).Mul(p, q)
	if !validResidue(c, n) || !p.ProbablyPrime(32) || !q.ProbablyPrime(32) {
		return nil, ErrInvalidInput
	}
	return CRT([]*big.Int{p, q}, []*big.Int{new(big.Int).Exp(c, dp, p), new(big.Int).Exp(c, dq, q)})
}

// IntegerToBytes returns the unsigned big-endian encoding of x. Width zero
// uses the shortest encoding, with zero represented by one zero byte. A positive
// width left-pads with zeros. Negative x/width or insufficient width are errors.
// A requested positive width is allocated in full; callers should bound widths
// originating from untrusted inputs.
func IntegerToBytes(x *big.Int, width int) ([]byte, error) {
	if x == nil || x.Sign() < 0 || width < 0 {
		return nil, ErrInvalidInput
	}
	size := (x.BitLen() + 7) / 8
	if size == 0 {
		size = 1
	}
	if width == 0 {
		width = size
	}
	if width < size {
		return nil, ErrInvalidInput
	}
	return x.FillBytes(make([]byte, width)), nil
}
