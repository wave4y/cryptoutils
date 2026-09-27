package cryptoutils_test

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	c "github.com/wave4y/cryptoutils"
)

func rsaContextCalls() []struct {
	name string
	call func(context.Context) (*big.Int, error)
} {
	return []struct {
		name string
		call func(context.Context) (*big.Int, error)
	}{
		{"root", func(ctx context.Context) (*big.Int, error) {
			root, _, err := c.RSAIntegerRootContext(ctx, big.NewInt(1000), 3)
			return root, err
		}},
		{"low_exponent", func(ctx context.Context) (*big.Int, error) {
			return c.RSALowExponentContext(ctx, big.NewInt(55), big.NewInt(3), big.NewInt(13), 6)
		}},
		{"fermat", func(ctx context.Context) (*big.Int, error) {
			return c.RSAFermatContext(ctx, big.NewInt(3233), 8)
		}},
		{"crt_leak", func(ctx context.Context) (*big.Int, error) {
			return c.RSAFactorFromCRTExponentContext(ctx, big.NewInt(11413), big.NewInt(1867), big.NewInt(3), 32)
		}},
	}
}

func TestRSAContextSuccessAndFailureStates(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, cleanup := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer cleanup()
	for _, operation := range rsaContextCalls() {
		t.Run(operation.name, func(t *testing.T) {
			result, err := operation.call(context.Background())
			if err != nil || result == nil {
				t.Fatalf("normal operation: %v, %v", result, err)
			}
			switch operation.name {
			case "root":
				if result.Int64() != 10 {
					t.Fatal("wrong integer root")
				}
			case "low_exponent":
				if result.Int64() != 7 {
					t.Fatal("wrong plaintext")
				}
			case "fermat":
				if result.Int64() != 53 && result.Int64() != 61 {
					t.Fatal("wrong factor")
				}
			case "crt_leak":
				if result.Int64() != 101 && result.Int64() != 113 {
					t.Fatal("wrong factor")
				}
			}
			for _, state := range []struct {
				ctx  context.Context
				want error
			}{{nil, c.ErrInvalidRSACTFInput}, {canceled, context.Canceled}, {expired, context.DeadlineExceeded}} {
				result, err := operation.call(state.ctx)
				if result != nil || !errors.Is(err, state.want) {
					t.Fatalf("got %v, %v; want nil, %v", result, err, state.want)
				}
			}
		})
	}
	if root, exact, err := c.RSAIntegerRootContext(canceled, big.NewInt(1000), 3); root != nil || exact || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled root exposed a partial result")
	}
}

// Trigger cancellation at an operation checkpoint without relying on machine
// speed, timers, goroutine scheduling, or a fixed wall-clock assertion.
type rsaCancelAfterChecks struct {
	context.Context
	cancel    context.CancelFunc
	remaining int
}

func (c *rsaCancelAfterChecks) Err() error {
	c.remaining--
	if c.remaining == 0 {
		c.cancel()
	}
	return c.Context.Err()
}

func TestRSAContextCancellationDuringWork(t *testing.T) {
	large := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 4096), big.NewInt(51))
	original := new(big.Int).Set(large)
	for _, operation := range []struct {
		name string
		call func(context.Context) (*big.Int, error)
	}{
		{"newton_iteration", func(ctx context.Context) (*big.Int, error) {
			root, _, err := c.RSAIntegerRootContext(ctx, large, 3)
			return root, err
		}},
		{"low_exponent_root", func(ctx context.Context) (*big.Int, error) {
			return c.RSALowExponentContext(ctx, large, big.NewInt(3), big.NewInt(17), ^uint64(0))
		}},
		{"fermat_candidates", func(ctx context.Context) (*big.Int, error) {
			return c.RSAFermatContext(ctx, big.NewInt(997), ^uint64(0))
		}},
		{"crt_repeated_squares", func(ctx context.Context) (*big.Int, error) {
			return c.RSAFactorFromCRTExponentContext(ctx, big.NewInt(257), big.NewInt(257), big.NewInt(1), ^uint64(0))
		}},
	} {
		t.Run(operation.name, func(t *testing.T) {
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx := &rsaCancelAfterChecks{Context: parent, cancel: cancel, remaining: 5}
			result, err := operation.call(ctx)
			if result != nil || !errors.Is(err, context.Canceled) {
				t.Fatalf("interrupted operation: %v, %v", result, err)
			}
		})
	}
	if large.Cmp(original) != 0 {
		t.Fatal("cancellation modified the input")
	}
}

func TestRSAContextBudgetSemantics(t *testing.T) {
	ctx := context.Background()
	for _, call := range []func() (*big.Int, error){
		func() (*big.Int, error) {
			return c.RSALowExponentContext(ctx, big.NewInt(55), big.NewInt(3), big.NewInt(13), 0)
		},
		func() (*big.Int, error) { return c.RSAFermatContext(ctx, big.NewInt(3233), 0) },
		func() (*big.Int, error) {
			return c.RSAFactorFromCRTExponentContext(ctx, big.NewInt(3233), big.NewInt(17), big.NewInt(53), 0)
		},
	} {
		if result, err := call(); result != nil || !errors.Is(err, c.ErrRSACTFNoResult) {
			t.Fatalf("zero budget: %v, %v", result, err)
		}
	}
	// LowExponent's budget is inclusive: maxK=0 still tests c itself.
	if m, err := c.RSALowExponentContext(ctx, big.NewInt(55), big.NewInt(3), big.NewInt(8), 0); err != nil || m.Int64() != 2 {
		t.Fatalf("k=0 root: %v, %v", m, err)
	}
	if factor, err := c.RSAFermatContext(ctx, big.NewInt(10), 0); err != nil || factor.Int64() != 2 {
		t.Fatalf("even modulus with zero search budget: %v, %v", factor, err)
	}
}
