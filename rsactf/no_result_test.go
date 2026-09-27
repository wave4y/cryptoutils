package rsactf_test

import (
	"errors"
	"math/big"
	"testing"

	"github.com/wave4y/cryptoutils/rsactf"
)

func TestNoResultSearchBoundaries(t *testing.T) {
	// For n=3, e=2, c=2, no canonical plaintext exists. k=2 still
	// considers floor(sqrt(8))=2; k=3 reaches floor(sqrt(11))=3=n.
	// For n=101, Fermat starts at a=11 and reaches 1*101 at a=51,
	// on candidate 41. These tests distinguish stopping from merely timing out.
	for _, tc := range []struct {
		name   string
		op     string
		call   func() (*big.Int, error)
		reason rsactf.NoResultReason
	}{
		{"low exponent budget", "LowExponent", func() (*big.Int, error) {
			return rsactf.LowExponent(integer(3), integer(2), integer(2), 2)
		}, rsactf.ReasonBudgetExhausted},
		{"low exponent exhausted at limit", "LowExponent", func() (*big.Int, error) {
			return rsactf.LowExponent(integer(3), integer(2), integer(2), 3)
		}, rsactf.ReasonSearchExhausted},
		{"fermat budget", "Fermat", func() (*big.Int, error) {
			return rsactf.Fermat(integer(101), 40)
		}, rsactf.ReasonBudgetExhausted},
		{"fermat exhausted at limit", "Fermat", func() (*big.Int, error) {
			return rsactf.Fermat(integer(101), 41)
		}, rsactf.ReasonSearchExhausted},
		{"crt exponent budget", "FactorFromCRTExponent", func() (*big.Int, error) {
			return rsactf.FactorFromCRTExponent(integer(7), integer(3), integer(1), 4)
		}, rsactf.ReasonBudgetExhausted},
		{"crt exponent exhausted at limit", "FactorFromCRTExponent", func() (*big.Int, error) {
			return rsactf.FactorFromCRTExponent(integer(7), integer(3), integer(1), 5)
		}, rsactf.ReasonSearchExhausted},
		{"crt exponent unusable relation", "FactorFromCRTExponent", func() (*big.Int, error) {
			return rsactf.FactorFromCRTExponent(integer(7), integer(1), integer(1), 5)
		}, rsactf.ReasonConditionsNotMet},
		{"crt exponent zero budget before relation", "FactorFromCRTExponent", func() (*big.Int, error) {
			return rsactf.FactorFromCRTExponent(integer(7), integer(1), integer(1), 0)
		}, rsactf.ReasonBudgetExhausted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.call()
			var detail *rsactf.NoResultError
			if got != nil || !errors.Is(err, rsactf.ErrNoResult) || !errors.As(err, &detail) {
				t.Fatalf("got %v, %v; want structured no result", got, err)
			}
			if detail.Op != tc.op || detail.Reason != tc.reason {
				t.Fatalf("got %+v; want %s, %s", detail, tc.op, tc.reason)
			}
		})
	}
}

func TestCommonModulusNoResultReasons(t *testing.T) {
	for _, tc := range []struct {
		name         string
		n, m, e1, e2 int64
		mismatch     bool
		reason       rsactf.NoResultReason
	}{
		{"fallback inverses absent", 3233, 53, 6, 9, false, rsactf.ReasonNotInvertible},
		{"fallback candidate fails verification", 11413, 101, 7, 11, true, rsactf.ReasonConditionsNotMet},
		{"fallback requires two primes", 45, 3, 7, 11, false, rsactf.ReasonConditionsNotMet},
		{"wrapped power is not an exact root", 3233, 20, 6, 9, false, rsactf.ReasonConditionsNotMet},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, e1, e2 := integer(tc.n), integer(tc.e1), integer(tc.e2)
			c1 := new(big.Int).Exp(integer(tc.m), e1, n)
			m2 := tc.m
			if tc.mismatch {
				m2++
			}
			c2 := new(big.Int).Exp(integer(m2), e2, n)
			got, err := rsactf.CommonModulus(n, e1, c1, e2, c2)
			var detail *rsactf.NoResultError
			if got != nil || !errors.Is(err, rsactf.ErrNoResult) || !errors.As(err, &detail) {
				t.Fatalf("got %v, %v; want structured no result", got, err)
			}
			if detail.Op != "CommonModulus" || detail.Reason != tc.reason {
				t.Fatalf("got %+v; want CommonModulus, %s", detail, tc.reason)
			}
		})
	}
}
