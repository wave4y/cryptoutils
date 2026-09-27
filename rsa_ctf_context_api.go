package cryptoutils

import (
	"context"
	"math/big"

	"github.com/wave4y/cryptoutils/rsactf"
)

// RSAIntegerRootContext is RSAIntegerRoot with cooperative cancellation.
// Individual math/big operations cannot be interrupted.
func RSAIntegerRootContext(ctx context.Context, x *big.Int, degree uint) (*big.Int, bool, error) {
	return rsactf.IntegerRootContext(ctx, x, degree)
}

// RSALowExponentContext is RSALowExponent with cooperative cancellation
// between candidates and within integer-root iteration.
func RSALowExponentContext(ctx context.Context, n, e, c *big.Int, maxK uint64) (*big.Int, error) {
	return rsactf.LowExponentContext(ctx, n, e, c, maxK)
}

// RSAFermatContext is RSAFermat with cooperative cancellation between candidates.
func RSAFermatContext(ctx context.Context, n *big.Int, maxSteps uint64) (*big.Int, error) {
	return rsactf.FermatContext(ctx, n, maxSteps)
}

// RSAFactorFromCRTExponentContext is RSAFactorFromCRTExponent with cooperative
// cancellation between bases, exponentiations, and repeated squares.
func RSAFactorFromCRTExponentContext(ctx context.Context, n, e, dp *big.Int, attempts uint64) (*big.Int, error) {
	return rsactf.FactorFromCRTExponentContext(ctx, n, e, dp, attempts)
}
