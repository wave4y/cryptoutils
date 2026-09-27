package rsactf_test

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/wave4y/cryptoutils/rsactf"
)

func TestFactorNoResultReasons(t *testing.T) {
	for _, tc := range []struct {
		name, op     string
		n, e         int64
		limit, tries uint64
		want         rsactf.NoResultReason
	}{
		{"Wiener zero terms", "Wiener", 101, 101, 0, 0, rsactf.ReasonBudgetExhausted},
		{"Wiener unfinished convergents", "Wiener", 90581, 17993, 1, 0, rsactf.ReasonBudgetExhausted},
		// e/n=1 has exactly one convergent. Completion takes precedence
		// when the last convergent coincides with the supplied term limit.
		{"Wiener completed at limit", "Wiener", 101, 101, 1, 0, rsactf.ReasonSearchExhausted},
		{"Wiener completed below limit", "Wiener", 101, 101, 2, 0, rsactf.ReasonSearchExhausted},
		{"p-1 zero attempts", "PollardPMinusOne", 38, 0, 2, 0, rsactf.ReasonBudgetExhausted},
		{"p-1 zero attempts without bases", "PollardPMinusOne", 2, 0, 2, 0, rsactf.ReasonBudgetExhausted},
		{"p-1 bases remain", "PollardPMinusOne", 5, 0, 2, 1, rsactf.ReasonBudgetExhausted},
		{"p-1 no possible base", "PollardPMinusOne", 2, 0, 2, 1, rsactf.ReasonSearchExhausted},
		// [2,3) contains one base; no proper factor exists for n=3.
		{"p-1 completed at limit", "PollardPMinusOne", 3, 0, 2, 1, rsactf.ReasonSearchExhausted},
		{"p-1 completed below limit", "PollardPMinusOne", 3, 0, 2, 2, rsactf.ReasonSearchExhausted},
		{"rho zero steps", "PollardRho", 2, 0, 0, 1, rsactf.ReasonBudgetExhausted},
		{"rho zero walks", "PollardRho", 2, 0, 1, 0, rsactf.ReasonBudgetExhausted},
		{"rho no possible factor", "PollardRho", 2, 0, 1, 1, rsactf.ReasonSearchExhausted},
		{"rho evaluation limit", "PollardRho", 15, 0, 1, 16, rsactf.ReasonBudgetExhausted},
		{"rho replay evaluation limit", "PollardRho", 25, 0, 6, 16, rsactf.ReasonBudgetExhausted},
		{"rho walk limit", "PollardRho", 25, 0, 10000, 1, rsactf.ReasonBudgetExhausted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, withContext := range []bool{false, true} {
				var factor *big.Int
				var err error
				n, e := big.NewInt(tc.n), big.NewInt(tc.e)
				switch tc.op {
				case "Wiener":
					if withContext {
						factor, err = rsactf.WienerContext(context.Background(), n, e, tc.limit)
					} else {
						factor, err = rsactf.Wiener(n, e, tc.limit)
					}
				case "PollardPMinusOne":
					if withContext {
						factor, err = rsactf.PollardPMinusOneContext(context.Background(), n, tc.limit, tc.tries)
					} else {
						factor, err = rsactf.PollardPMinusOne(n, tc.limit, tc.tries)
					}
				case "PollardRho":
					if withContext {
						factor, err = rsactf.PollardRhoContext(context.Background(), n, tc.limit, tc.tries)
					} else {
						factor, err = rsactf.PollardRho(n, tc.limit, tc.tries)
					}
				}
				if factor != nil || !errors.Is(err, rsactf.ErrNoResult) {
					t.Fatalf("Context=%v: got (%v, %v), want nil and ErrNoResult", withContext, factor, err)
				}
				// Consumers must retain both the sentinel and the detailed
				// reason through an additional application error wrapper.
				wrapped := fmt.Errorf("factor request: %w", err)
				var detail *rsactf.NoResultError
				if !errors.Is(wrapped, rsactf.ErrNoResult) || !errors.As(wrapped, &detail) {
					t.Fatalf("Context=%v: lost error compatibility: %v", withContext, wrapped)
				}
				if detail.Op != tc.op || detail.Reason != tc.want {
					t.Fatalf("Context=%v: got Op=%q Reason=%q, want %q %q", withContext, detail.Op, detail.Reason, tc.op, tc.want)
				}
				if n.Int64() != tc.n || e.Int64() != tc.e {
					t.Fatal("failure modified an input")
				}
			}
		})
	}
}

func TestFactorReasonsPreserveSuccessAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		name string
		want int64
		call func(context.Context) (*big.Int, error)
	}{
		{"Wiener", 239, func(ctx context.Context) (*big.Int, error) {
			return rsactf.WienerContext(ctx, big.NewInt(90581), big.NewInt(17993), 2)
		}},
		{"PollardPMinusOne", 2, func(ctx context.Context) (*big.Int, error) {
			return rsactf.PollardPMinusOneContext(ctx, big.NewInt(38), 2, 1)
		}},
		{"PollardRho", 5, func(ctx context.Context) (*big.Int, error) {
			return rsactf.PollardRhoContext(ctx, big.NewInt(25), 9, 2)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			factor, err := tc.call(context.Background())
			requireInteger(t, factor, err, tc.want)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			factor, err = tc.call(ctx)
			var detail *rsactf.NoResultError
			if factor != nil || !errors.Is(err, context.Canceled) || errors.Is(err, rsactf.ErrNoResult) || errors.As(err, &detail) {
				t.Fatalf("cancellation became a no-result error: (%v, %v)", factor, err)
			}
		})
	}
}
