package rsactf

import "math/big"

// PublicParameters holds textbook RSA integers without the key-size or
// machine-integer exponent restrictions of crypto/rsa.PublicKey.
type PublicParameters struct {
	N, E *big.Int
}

// PrivateParameters holds a completed two-prime textbook RSA key. D is the
// least positive inverse of E modulo Lambda, not necessarily modulo Phi.
// Values returned by CompletePrivateParameters do not alias one another or
// any input. The fields are mutable; callers must preserve their relationships.
type PrivateParameters struct {
	PublicParameters
	D, P, Q, DP, DQ, Phi, Lambda *big.Int
}

// PrivateExponent returns the least positive inverse of e modulo totient.
// Both inputs must be greater than one. totient may be phi(n) or lambda(n);
// without n this function cannot validate that it is the correct value.
// A noninvertible exponent returns ErrNoResult. Neither input is modified.
func PrivateExponent(e, totient *big.Int) (*big.Int, error) {
	if !validModulus(e) || !validModulus(totient) {
		return nil, ErrInvalidInput
	}
	d := new(big.Int).ModInverse(e, totient)
	if d == nil {
		return nil, ErrNoResult
	}
	return d, nil
}

// CompletePrivateParameters derives N, Phi, Lambda, D, DP, and DQ from p, q,
// and e. It requires distinct odd probable primes and e > 1. It accepts small
// primes and arbitrary-size exponents; it does not enforce padded RSA policy.
// An exponent not coprime to lambda(p*q) returns ErrNoResult. All other invalid
// inputs return ErrInvalidInput. Inputs are preserved and outputs are independent.
func CompletePrivateParameters(p, q, e *big.Int) (*PrivateParameters, error) {
	if !validModulus(p) || !validModulus(q) || !validModulus(e) ||
		p.Bit(0) == 0 || q.Bit(0) == 0 || p.Cmp(q) == 0 ||
		!p.ProbablyPrime(32) || !q.ProbablyPrime(32) {
		return nil, ErrInvalidInput
	}
	one := big.NewInt(1)
	pMinusOne := new(big.Int).Sub(p, one)
	qMinusOne := new(big.Int).Sub(q, one)
	phi := new(big.Int).Mul(pMinusOne, qMinusOne)
	gcd := new(big.Int).GCD(nil, nil, pMinusOne, qMinusOne)
	lambda := new(big.Int).Quo(phi, gcd)
	d, err := PrivateExponent(e, lambda)
	if err != nil {
		return nil, err
	}
	return &PrivateParameters{
		PublicParameters: PublicParameters{
			N: new(big.Int).Mul(p, q),
			E: new(big.Int).Set(e),
		},
		D:      d,
		P:      new(big.Int).Set(p),
		Q:      new(big.Int).Set(q),
		DP:     new(big.Int).Mod(d, pMinusOne),
		DQ:     new(big.Int).Mod(d, qMinusOne),
		Phi:    phi,
		Lambda: lambda,
	}, nil
}
