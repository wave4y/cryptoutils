package rsactf

import (
	"context"
	"math/big"
)

// Wiener searches the continued-fraction convergents k/d of e/n for a small
// private exponent satisfying e*d-1=k*phi(n). It requires n > 1 and e > 1.
// A result is a nontrivial factor of n, verified as one of two distinct
// probable primes. It examines at most maxConvergents terms, including an
// initial k=0 term when e<n. Zero performs no search. This is the classical
// convergent search, without semiconvergents or extensions; ErrNoResult does
// not prove that the key has no small private exponent.
func Wiener(n, e *big.Int, maxConvergents uint64) (*big.Int, error) {
	return WienerContext(context.Background(), n, e, maxConvergents)
}

// WienerContext is Wiener with cooperative cancellation between convergents
// and candidate checks. It cannot interrupt an individual math/big operation
// or the two-prime validation in FactorFromPhi. A nil context is invalid;
// cancellation returns ctx.Err() and no factor.
func WienerContext(ctx context.Context, n, e *big.Int, maxConvergents uint64) (*big.Int, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if !validModulus(n) || !validModulus(e) {
		return nil, ErrInvalidInput
	}
	if maxConvergents == 0 {
		return nil, ErrNoResult
	}

	numerator, denominator := new(big.Int).Set(e), new(big.Int).Set(n)
	// The recurrence starts with k[-2]/d[-2]=0/1 and k[-1]/d[-1]=1/0.
	kPrevious, kCurrent := new(big.Int), big.NewInt(1)
	dPrevious, dCurrent := big.NewInt(1), new(big.Int)
	one := big.NewInt(1)
	for term := uint64(0); term < maxConvergents && denominator.Sign() != 0; term++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		quotient, remainder := new(big.Int), new(big.Int)
		quotient.QuoRem(numerator, denominator, remainder)
		k := new(big.Int).Add(new(big.Int).Mul(quotient, kCurrent), kPrevious)
		d := new(big.Int).Add(new(big.Int).Mul(quotient, dCurrent), dPrevious)
		numerator, denominator = denominator, remainder
		kPrevious, kCurrent = kCurrent, k
		dPrevious, dCurrent = dCurrent, d
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if k.Sign() == 0 {
			continue
		}

		edMinusOne := new(big.Int).Sub(new(big.Int).Mul(e, d), one)
		phi, residue := new(big.Int), new(big.Int)
		phi.QuoRem(edMinusOne, k, residue)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if residue.Sign() != 0 || phi.Sign() <= 0 || phi.Cmp(n) >= 0 {
			continue
		}
		factor, err := FactorFromPhi(n, phi)
		if contextErr := ctx.Err(); contextErr != nil {
			return nil, contextErr
		}
		if err == nil {
			return factor, nil
		}
	}
	return nil, ErrNoResult
}
