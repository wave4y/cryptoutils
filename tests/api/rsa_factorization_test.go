package cryptoutils_test

import (
	"context"
	"errors"
	"math/big"
	"testing"

	c "github.com/wave4y/cryptoutils"
)

func TestRSAFactorizationWorkflows(t *testing.T) {
	for _, tc := range []struct {
		name string
		n, e int64
		find func(*big.Int, *big.Int) (*big.Int, error)
	}{
		{"wiener", 90581, 17993, func(n, e *big.Int) (*big.Int, error) { return c.RSAWiener(n, e, 2) }},
		{"pollard_pm1", 257 * 1019, 65537, func(n, _ *big.Int) (*big.Int, error) { return c.RSAPollardPMinusOne(n, 256, 3) }},
		{"pollard_rho", 83 * 97, 17, func(n, _ *big.Int) (*big.Int, error) { return c.RSAPollardRho(n, 10000, 8) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, e, message := big.NewInt(tc.n), big.NewInt(tc.e), big.NewInt(42)
			ciphertext, err := c.EncryptRSARaw(n, e, message)
			if err != nil {
				t.Fatal(err)
			}
			factor, err := tc.find(n, e)
			if err != nil {
				t.Fatal(err)
			}
			q, remainder := new(big.Int), new(big.Int)
			q.QuoRem(n, factor, remainder)
			if remainder.Sign() != 0 || factor.Cmp(big.NewInt(1)) <= 0 || q.Cmp(big.NewInt(1)) <= 0 {
				t.Fatal("not a proper factor")
			}
			params, err := c.RSACompletePrivateParameters(factor, q, e)
			if err != nil {
				t.Fatal(err)
			}
			plain, err := c.DecryptRSARaw(params.N, params.D, ciphertext)
			if err != nil || plain.Cmp(message) != 0 {
				t.Fatalf("factor-to-plaintext workflow: %v, %v", plain, err)
			}
		})
	}
}

func TestRSAFactorizationErrorsAndContexts(t *testing.T) {
	for _, call := range []func() (*big.Int, error){
		func() (*big.Int, error) { return c.RSAWiener(big.NewInt(90581), big.NewInt(17993), 0) },
		func() (*big.Int, error) { return c.RSAPollardPMinusOne(big.NewInt(8051), 100, 0) },
		func() (*big.Int, error) { return c.RSAPollardRho(big.NewInt(8051), 0, 8) },
		func() (*big.Int, error) { return c.RSAPollardRho(big.NewInt(8051), 10000, 0) },
	} {
		if factor, err := call(); factor != nil || !errors.Is(err, c.ErrRSACTFNoResult) {
			t.Fatalf("zero budget: %v, %v", factor, err)
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, call := range []func(context.Context) (*big.Int, error){
		func(ctx context.Context) (*big.Int, error) {
			return c.RSAWienerContext(ctx, big.NewInt(90581), big.NewInt(17993), 10)
		},
		func(ctx context.Context) (*big.Int, error) {
			return c.RSAPollardPMinusOneContext(ctx, big.NewInt(8051), 100, 4)
		},
		func(ctx context.Context) (*big.Int, error) {
			return c.RSAPollardRhoContext(ctx, big.NewInt(8051), 10000, 8)
		},
	} {
		if factor, err := call(nil); factor != nil || !errors.Is(err, c.ErrInvalidRSACTFInput) {
			t.Fatalf("nil context: %v, %v", factor, err)
		}
		if factor, err := call(canceled); factor != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled context: %v, %v", factor, err)
		}
	}
}
