package cryptoutils

import (
	"math/big"

	"github.com/wave4y/cryptoutils/rsactf"
)

var (
	// ErrInvalidRSACTFInput indicates invalid inputs to the RSA math/CTF APIs.
	ErrInvalidRSACTFInput = rsactf.ErrInvalidInput
	// ErrRSACTFNoResult means the attack found no result under its conditions or budget.
	ErrRSACTFNoResult = rsactf.ErrNoResult
)

// EncryptRSARaw computes m^e mod n without padding. This variable-time research
// primitive accepts small moduli and arbitrary-size exponents; use RSA-OAEP for applications.
func EncryptRSARaw(n, e, m *big.Int) (*big.Int, error) { return rsactf.EncryptRaw(n, e, m) }

// DecryptRSARaw computes c^d mod n using only n, d and c. It does not validate a
// private key or decode padding. All input big.Int values are preserved.
func DecryptRSARaw(n, d, c *big.Int) (*big.Int, error) { return rsactf.DecryptRaw(n, d, c) }

// DecryptRSACRT combines local decryptions for distinct odd probable primes p and q.
// The caller supplies reduced positive dp/dq and a ciphertext in [0,p*q).
func DecryptRSACRT(p, q, dp, dq, c *big.Int) (*big.Int, error) {
	return rsactf.DecryptCRT(p, q, dp, dq, c)
}

// RSAIntegerToBytes encodes a nonnegative integer. Width zero uses a minimal
// encoding (one byte for zero); positive width pads on the left, or errors if too small.
func RSAIntegerToBytes(x *big.Int, width int) ([]byte, error) { return rsactf.IntegerToBytes(x, width) }

// RSAIntegerRoot returns floor(x^(1/degree)), whether it is exact, and any input error.
func RSAIntegerRoot(x *big.Int, degree uint) (*big.Int, bool, error) {
	return rsactf.IntegerRoot(x, degree)
}

// RSACRT combines canonical residues under at least two pairwise coprime moduli.
func RSACRT(moduli, residues []*big.Int) (*big.Int, error) { return rsactf.CRT(moduli, residues) }

// RSALowExponent tests c+k*n for an exact e-th root, for k=0..maxK and 2<=e<=64.
func RSALowExponent(n, e, c *big.Int, maxK uint64) (*big.Int, error) {
	return rsactf.LowExponent(n, e, c, maxK)
}

// RSABroadcast recovers a shared plaintext by CRT and exact rooting, for 2<=e<=64.
func RSABroadcast(moduli, ciphertexts []*big.Int, e uint) (*big.Int, error) {
	return rsactf.Broadcast(moduli, ciphertexts, e)
}

// RSACommonModulus combines two encryptions of one plaintext. For noncoprime
// exponents it attempts an exact root; a ciphertext exposing a factor can also
// enable two-prime recovery. Every result is checked against both ciphertexts.
func RSACommonModulus(n, e1, c1, e2, c2 *big.Int) (*big.Int, error) {
	return rsactf.CommonModulus(n, e1, c1, e2, c2)
}

// RSASharedFactor returns a common factor that is nontrivial for both moduli.
func RSASharedFactor(n1, n2 *big.Int) (*big.Int, error) { return rsactf.SharedFactor(n1, n2) }

// RSAFermat tests at most maxSteps square candidates for an odd n; even n>2 yields 2.
func RSAFermat(n *big.Int, maxSteps uint64) (*big.Int, error) { return rsactf.Fermat(n, maxSteps) }

// RSAFactorFromPhi recovers a prime factor given n=p*q and phi=(p-1)*(q-1), p!=q.
func RSAFactorFromPhi(n, phi *big.Int) (*big.Int, error) { return rsactf.FactorFromPhi(n, phi) }

// RSAFactorFromCRTExponent tries attempts bases to recover a factor from a
// leaked dp or dq, including a repeated-squaring fallback for a trivial GCD.
func RSAFactorFromCRTExponent(n, e, dp *big.Int, attempts uint64) (*big.Int, error) {
	return rsactf.FactorFromCRTExponent(n, e, dp, attempts)
}

// RSARawEncrypt interprets current bytes as an unsigned integer and applies
// unpadded RSA. Output is raw bytes padded to the modulus width. Empty input is zero.
func (p *CryptoData) RSARawEncrypt(n, e *big.Int) *CryptoData {
	if p.err != nil {
		return p
	}
	ciphertext, err := EncryptRSARaw(n, e, new(big.Int).SetBytes(p.data))
	if err != nil {
		return p.fail(err)
	}
	out, err := RSAIntegerToBytes(ciphertext, (n.BitLen()+7)/8)
	return p.setAsymmetricResult(out, err)
}

// RSARawDecrypt applies unpadded RSA to current bytes as an unsigned integer.
// Width zero returns minimal bytes (one zero byte for zero); positive width
// left-pads the result. It cannot infer the original number of leading zero bytes.
func (p *CryptoData) RSARawDecrypt(n, d *big.Int, width int) *CryptoData {
	if p.err != nil {
		return p
	}
	if width < 0 {
		return p.fail(ErrInvalidRSACTFInput)
	}
	plaintext, err := DecryptRSARaw(n, d, new(big.Int).SetBytes(p.data))
	if err != nil {
		return p.fail(err)
	}
	out, err := RSAIntegerToBytes(plaintext, width)
	return p.setAsymmetricResult(out, err)
}
