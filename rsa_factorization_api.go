package cryptoutils

import (
	"context"
	"math/big"

	"github.com/wave4y/cryptoutils/rsactf"
)

// RSAWiener returns a prime factor recovered by the classical continued-fraction
// attack on a small private exponent. maxConvergents bounds examined convergents,
// including the initial zero-numerator convergent when e < n. It returns a
// factor, not d; use RSACompletePrivateParameters to derive private parameters.
func RSAWiener(n, e *big.Int, maxConvergents uint64) (*big.Int, error) {
	return rsactf.Wiener(n, e, maxConvergents)
}

// RSAWienerContext is RSAWiener with cooperative cancellation.
func RSAWienerContext(ctx context.Context, n, e *big.Int, maxConvergents uint64) (*big.Int, error) {
	return rsactf.WienerContext(ctx, n, e, maxConvergents)
}

// RSAPollardPMinusOne attempts stage-one Pollard p-1 factorization. bound is
// the smoothness bound (at least 2); attempts limits bases starting at 2.
// A recovered factor is nontrivial but need not itself be prime.
func RSAPollardPMinusOne(n *big.Int, bound, attempts uint64) (*big.Int, error) {
	return rsactf.PollardPMinusOne(n, bound, attempts)
}

// RSAPollardPMinusOneContext is RSAPollardPMinusOne with cooperative cancellation.
func RSAPollardPMinusOneContext(ctx context.Context, n *big.Int, bound, attempts uint64) (*big.Int, error) {
	return rsactf.PollardPMinusOneContext(ctx, n, bound, attempts)
}

// RSAPollardRho attempts bounded Pollard rho factorization. maxSteps limits
// polynomial evaluations across all attempts, including failed-batch replay;
// attempts limits restarts. A factor need not itself be prime.
func RSAPollardRho(n *big.Int, maxSteps, attempts uint64) (*big.Int, error) {
	return rsactf.PollardRho(n, maxSteps, attempts)
}

// RSAPollardRhoContext is RSAPollardRho with cooperative cancellation.
func RSAPollardRhoContext(ctx context.Context, n *big.Int, maxSteps, attempts uint64) (*big.Int, error) {
	return rsactf.PollardRhoContext(ctx, n, maxSteps, attempts)
}
