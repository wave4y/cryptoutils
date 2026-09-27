package cryptoutils

import (
	"math/big"

	"github.com/wave4y/cryptoutils/rsactf"
)

// RSAPublicParameters holds arbitrary-size RSA integers for CTF analysis.
// It does not impose the application RSA key policy used by OAEP/PSS.
type RSAPublicParameters = rsactf.PublicParameters

// RSAPrivateParameters holds a completed two-prime RSA parameter set.
// Completion validates distinct odd probable primes and derives D modulo Lambda.
type RSAPrivateParameters = rsactf.PrivateParameters

// ParseRSAPublicParametersDER reads PKCS#1 or PKIX RSA public parameters,
// accepting small moduli and arbitrary-size positive exponents. It rejects
// malformed or trailing data. This does not validate an application RSA key.
func ParseRSAPublicParametersDER(der []byte) (*RSAPublicParameters, error) {
	return rsactf.ParsePublicKeyDER(der)
}

// ParseRSAPublicParametersPEM reads one RSA PUBLIC KEY or PUBLIC KEY block
// under the same parameter rules as ParseRSAPublicParametersDER.
func ParseRSAPublicParametersPEM(encoded []byte) (*RSAPublicParameters, error) {
	return rsactf.ParsePublicKeyPEM(encoded)
}

// RSACompletePrivateParameters derives N, Phi, Lambda, D, DP and DQ from
// distinct odd probable primes p/q and an exponent e > 1 coprime to Lambda.
// All returned integers are independent copies. Square/multi-prime RSA is
// outside this constructor's scope.
func RSACompletePrivateParameters(p, q, e *big.Int) (*RSAPrivateParameters, error) {
	return rsactf.CompletePrivateParameters(p, q, e)
}

// RSAPrivateExponent computes e^-1 modulo a supplied phi or lambda (> 1).
// It cannot establish that the totient belongs to a particular modulus.
func RSAPrivateExponent(e, totient *big.Int) (*big.Int, error) {
	return rsactf.PrivateExponent(e, totient)
}
