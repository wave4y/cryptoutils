package cryptoutils_test

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	c "github.com/wave4y/cryptoutils"
	"github.com/wave4y/cryptoutils/rsactf"
)

func requireRSANoResult(t *testing.T, err error, op string, reason c.RSACTFNoResultReason) {
	t.Helper()
	// Application-level wrapping must preserve both package entry points.
	wrapped := fmt.Errorf("solve challenge: %w", err)
	if !errors.Is(wrapped, c.ErrRSACTFNoResult) || !errors.Is(wrapped, rsactf.ErrNoResult) {
		t.Fatalf("got %v; want an error matching both no-result sentinels", wrapped)
	}
	var rootDetail *c.RSACTFNoResultError
	var packageDetail *rsactf.NoResultError
	if !errors.As(wrapped, &rootDetail) || !errors.As(wrapped, &packageDetail) {
		t.Fatalf("got %v; want a typed no-result error through either package", wrapped)
	}
	if rootDetail != packageDetail || rootDetail.Op != op || rootDetail.Reason != reason {
		t.Fatalf("got %+v; want Op=%q Reason=%q with identical alias pointers", rootDetail, op, reason)
	}
	if errors.Is(wrapped, c.ErrInvalidRSACTFInput) || errors.Is(wrapped, context.Canceled) || errors.Is(wrapped, context.DeadlineExceeded) {
		t.Fatalf("no-result error also matched an unrelated failure: %v", wrapped)
	}
}

func TestRSANoResultReasons(t *testing.T) {
	for _, tc := range []struct {
		name, op string
		reason   c.RSACTFNoResultReason
		call     func() (*big.Int, error)
	}{
		{"low_exponent_budget", "LowExponent", c.RSACTFReasonBudgetExhausted, func() (*big.Int, error) {
			return c.RSALowExponent(big.NewInt(55), big.NewInt(3), big.NewInt(13), 0)
		}},
		{"broadcast_conditions", "Broadcast", c.RSACTFReasonConditionsNotMet, func() (*big.Int, error) {
			return c.RSABroadcast([]*big.Int{big.NewInt(5), big.NewInt(7)}, []*big.Int{big.NewInt(2), big.NewInt(2)}, 3)
		}},
		{"common_modulus_conditions", "CommonModulus", c.RSACTFReasonConditionsNotMet, func() (*big.Int, error) {
			return c.RSACommonModulus(big.NewInt(15), big.NewInt(2), big.NewInt(2), big.NewInt(3), big.NewInt(2))
		}},
		{"shared_factor_conditions", "SharedFactor", c.RSACTFReasonConditionsNotMet, func() (*big.Int, error) {
			return c.RSASharedFactor(big.NewInt(35), big.NewInt(143))
		}},
		{"fermat_budget", "Fermat", c.RSACTFReasonBudgetExhausted, func() (*big.Int, error) {
			return c.RSAFermat(big.NewInt(101), 1)
		}},
		{"fermat_search", "Fermat", c.RSACTFReasonSearchExhausted, func() (*big.Int, error) {
			return c.RSAFermat(big.NewInt(101), 42)
		}},
		{"phi_conditions", "FactorFromPhi", c.RSACTFReasonConditionsNotMet, func() (*big.Int, error) {
			return c.RSAFactorFromPhi(big.NewInt(35), big.NewInt(25))
		}},
		{"crt_exponent_budget", "FactorFromCRTExponent", c.RSACTFReasonBudgetExhausted, func() (*big.Int, error) {
			return c.RSAFactorFromCRTExponent(big.NewInt(101), big.NewInt(3), big.NewInt(1), 1)
		}},
		{"crt_exponent_search", "FactorFromCRTExponent", c.RSACTFReasonSearchExhausted, func() (*big.Int, error) {
			return c.RSAFactorFromCRTExponent(big.NewInt(101), big.NewInt(3), big.NewInt(1), 99)
		}},
		{"private_exponent_inverse", "PrivateExponent", c.RSACTFReasonNotInvertible, func() (*big.Int, error) {
			return c.RSAPrivateExponent(big.NewInt(6), big.NewInt(10))
		}},
		{"wiener_budget", "Wiener", c.RSACTFReasonBudgetExhausted, func() (*big.Int, error) {
			return c.RSAWiener(big.NewInt(90581), big.NewInt(17993), 1)
		}},
		{"wiener_search", "Wiener", c.RSACTFReasonSearchExhausted, func() (*big.Int, error) {
			return c.RSAWiener(big.NewInt(101), big.NewInt(3), 100)
		}},
		{"pollard_pm1_budget", "PollardPMinusOne", c.RSACTFReasonBudgetExhausted, func() (*big.Int, error) {
			return c.RSAPollardPMinusOne(big.NewInt(101), 2, 1)
		}},
		{"pollard_rho_budget", "PollardRho", c.RSACTFReasonBudgetExhausted, func() (*big.Int, error) {
			return c.RSAPollardRho(big.NewInt(101), 1, 1)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := tc.call()
			if result != nil {
				t.Fatalf("failed search exposed a result: %v", result)
			}
			requireRSANoResult(t, err, tc.op, tc.reason)
		})
	}
	params, err := c.RSACompletePrivateParameters(big.NewInt(5), big.NewInt(11), big.NewInt(2))
	if params != nil {
		t.Fatalf("failed parameter completion exposed a result: %+v", params)
	}
	requireRSANoResult(t, err, "CompletePrivateParameters", c.RSACTFReasonNotInvertible)
}

func TestRSANoResultAliases(t *testing.T) {
	for _, pair := range [][2]rsactf.NoResultReason{
		{c.RSACTFReasonBudgetExhausted, rsactf.ReasonBudgetExhausted},
		{c.RSACTFReasonSearchExhausted, rsactf.ReasonSearchExhausted},
		{c.RSACTFReasonConditionsNotMet, rsactf.ReasonConditionsNotMet},
		{c.RSACTFReasonNotInvertible, rsactf.ReasonNotInvertible},
	} {
		if pair[0] != pair[1] {
			t.Fatalf("root/subpackage reason aliases differ: %q != %q", pair[0], pair[1])
		}
	}
	_, err := rsactf.PrivateExponent(big.NewInt(6), big.NewInt(10))
	requireRSANoResult(t, err, "PrivateExponent", c.RSACTFReasonNotInvertible)
	if c.ErrRSACTFNoResult != rsactf.ErrNoResult {
		t.Fatal("root and subpackage no-result sentinels must remain identical")
	}
}

func TestRSANoResultContextSeparation(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, cleanup := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer cleanup()
	for _, operation := range []struct {
		op   string
		call func(context.Context) (*big.Int, error)
	}{
		{"LowExponent", func(ctx context.Context) (*big.Int, error) {
			return c.RSALowExponentContext(ctx, big.NewInt(55), big.NewInt(3), big.NewInt(13), 0)
		}},
		{"Fermat", func(ctx context.Context) (*big.Int, error) {
			return c.RSAFermatContext(ctx, big.NewInt(101), 1)
		}},
		{"FactorFromCRTExponent", func(ctx context.Context) (*big.Int, error) {
			return c.RSAFactorFromCRTExponentContext(ctx, big.NewInt(101), big.NewInt(3), big.NewInt(1), 1)
		}},
		{"Wiener", func(ctx context.Context) (*big.Int, error) {
			return c.RSAWienerContext(ctx, big.NewInt(101), big.NewInt(3), 1)
		}},
		{"PollardPMinusOne", func(ctx context.Context) (*big.Int, error) {
			return c.RSAPollardPMinusOneContext(ctx, big.NewInt(101), 2, 1)
		}},
		{"PollardRho", func(ctx context.Context) (*big.Int, error) {
			return c.RSAPollardRhoContext(ctx, big.NewInt(101), 1, 1)
		}},
	} {
		t.Run(operation.op, func(t *testing.T) {
			result, err := operation.call(context.Background())
			if result != nil {
				t.Fatalf("failed context search exposed a result: %v", result)
			}
			requireRSANoResult(t, err, operation.op, c.RSACTFReasonBudgetExhausted)
			for _, state := range []struct {
				ctx  context.Context
				want error
			}{{nil, c.ErrInvalidRSACTFInput}, {canceled, context.Canceled}, {expired, context.DeadlineExceeded}} {
				result, err := operation.call(state.ctx)
				var detail *c.RSACTFNoResultError
				if result != nil || !errors.Is(err, state.want) || errors.Is(err, c.ErrRSACTFNoResult) || errors.As(err, &detail) {
					t.Fatalf("got %v, %v; want only %v, without a search failure reason", result, err, state.want)
				}
			}
		})
	}
	if _, err := c.RSAPrivateExponent(nil, big.NewInt(10)); !errors.Is(err, c.ErrInvalidRSACTFInput) || errors.Is(err, c.ErrRSACTFNoResult) {
		t.Fatalf("invalid exponent must remain distinct from a noninvertible exponent: %v", err)
	}
}
