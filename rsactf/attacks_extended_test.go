package rsactf_test

import (
	"errors"
	"math/big"
	"testing"

	"github.com/wave4y/cryptoutils/rsactf"
)

func TestCommonModulusNoncoprimeExponents(t *testing.T) {
	// RsaCtfTool examples/common_modulus{1,2}.pub use e=6/9,
	// n=3233 and ciphertexts 0x785/0xb3c for the plaintext 12.
	plain, err := rsactf.CommonModulus(integer(3233), integer(6), integer(1925), integer(9), integer(2876))
	requireInteger(t, plain, err, 12)
	plain, err = rsactf.CommonModulus(integer(3233), integer(9), integer(2876), integer(6), integer(1925))
	requireInteger(t, plain, err, 12)

	for _, m := range []int64{0, 1, 2, 14} {
		n, e1, e2 := integer(3233), integer(6), integer(9)
		c1, c2 := new(big.Int).Exp(integer(m), e1, n), new(big.Int).Exp(integer(m), e2, n)
		plain, err = rsactf.CommonModulus(n, e1, c1, e2, c2)
		requireInteger(t, plain, err, m)
	}

	// The integer-root branch does not search across multiples of n.
	n, e1, e2 := integer(3233), integer(6), integer(9)
	c1 := new(big.Int).Exp(integer(20), e1, n)
	c2 := new(big.Int).Exp(integer(20), e2, n)
	_, err = rsactf.CommonModulus(n, e1, c1, e2, c2)
	requireError(t, err, rsactf.ErrNoResult)
	// A small root alone is insufficient: both observations must match.
	_, err = rsactf.CommonModulus(n, e1, integer(1925), e2, integer(1))
	requireError(t, err, rsactf.ErrNoResult)
}

func TestCommonModulusHugeExponentGCD(t *testing.T) {
	n := integer(3233)
	e1 := new(big.Int).Lsh(integer(1), 100)
	e2 := new(big.Int).Mul(e1, integer(3))
	for _, m := range []int64{0, 1} {
		plain, err := rsactf.CommonModulus(n, e1, integer(m), e2, integer(m))
		requireInteger(t, plain, err, m)
	}
	c1, c2 := new(big.Int).Exp(integer(2), e1, n), new(big.Int).Exp(integer(2), e2, n)
	_, err := rsactf.CommonModulus(n, e1, c1, e2, c2)
	requireError(t, err, rsactf.ErrNoResult)
}

func TestCommonModulusFactorRecovery(t *testing.T) {
	for _, exponents := range [][2]int64{{7, 11}, {11, 7}, {6, 11}, {11, 6}} {
		n, m := integer(11413), integer(101)
		e1, e2 := integer(exponents[0]), integer(exponents[1])
		c1, c2 := new(big.Int).Exp(m, e1, n), new(big.Int).Exp(m, e2, n)
		plain, err := rsactf.CommonModulus(n, e1, c1, e2, c2)
		requireInteger(t, plain, err, 101)
		_, err = rsactf.CommonModulus(n, e1, c1, e2, new(big.Int).Exp(integer(102), e2, n))
		requireError(t, err, rsactf.ErrNoResult)
	}

	for _, tc := range []struct {
		name         string
		n, m, e1, e2 int64
	}{
		{"neither exponent invertible", 3233, 53, 6, 9},
		{"composite first factor", 45, 3, 7, 11},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, m := integer(tc.n), integer(tc.m)
			e1, e2 := integer(tc.e1), integer(tc.e2)
			c1, c2 := new(big.Int).Exp(m, e1, n), new(big.Int).Exp(m, e2, n)
			_, err := rsactf.CommonModulus(n, e1, c1, e2, c2)
			requireError(t, err, rsactf.ErrNoResult)
		})
	}
}

func TestCommonModulusPreservesGeneralModuli(t *testing.T) {
	// Exponent one can reveal the message without any factor assumptions.
	for _, tc := range [][2]int64{{49, 7}, {81, 3}} {
		n, m := integer(tc[0]), integer(tc[1])
		c2 := new(big.Int).Exp(m, integer(3), n)
		plain, err := rsactf.CommonModulus(n, integer(1), m, integer(3), c2)
		requireInteger(t, plain, err, tc[1])
	}
	// When exponent recovery fails, a factor of a square or a composite
	// cofactor must not be used as a two-prime RSA key.
	for _, tc := range [][3]int64{{49, 7, 0}, {81, 3, 27}} {
		_, err := rsactf.CommonModulus(integer(tc[0]), integer(3), integer(tc[1]), integer(5), integer(tc[2]))
		requireError(t, err, rsactf.ErrNoResult)
	}
}

func TestFactorFromCRTExponentRepeatedSquaring(t *testing.T) {
	// k=1867*3-1=5600 is a multiple of lambda(101*113)=2800.
	// Every unit therefore gives the trivial GCD n in the original method.
	n, e, dp := integer(11413), integer(1867), integer(3)
	factor, err := rsactf.FactorFromCRTExponent(n, e, dp, 32)
	requireFactor(t, n, factor, err)

	// A genuine dp leak need not satisfy e*dp=1 modulo lambda(n).
	n, e, dp = integer(3233), integer(17), integer(53)
	factor, err = rsactf.FactorFromCRTExponent(n, e, dp, 1)
	requireFactor(t, n, factor, err)
	// A bounded search can still miss a valid leak: base 2 alone cannot
	// distinguish the factors of 11*19 when e=13 and dp=7.
	_, err = rsactf.FactorFromCRTExponent(integer(209), integer(13), integer(7), 1)
	requireError(t, err, rsactf.ErrNoResult)
	_, err = rsactf.FactorFromCRTExponent(integer(11413), integer(1867), integer(3), 0)
	requireError(t, err, rsactf.ErrNoResult)
	_, err = rsactf.FactorFromCRTExponent(integer(101), integer(1867), integer(3), 32)
	requireError(t, err, rsactf.ErrNoResult)

	// Factoring does not assert a two-prime key: squares and composite
	// divisors are legitimate results, provided they divide n properly.
	factor, err = rsactf.FactorFromCRTExponent(integer(121), integer(7), integer(3), 1)
	requireFactor(t, integer(121), factor, err)
	factor, err = rsactf.FactorFromCRTExponent(integer(225), integer(5), integer(1), 1)
	requireInteger(t, factor, err, 15)
}

func TestExtendedAttacksDoNotMutateInputs(t *testing.T) {
	cases := []struct {
		name string
		args []*big.Int
		run  func([]*big.Int) (*big.Int, error)
	}{
		{"noncoprime root", []*big.Int{integer(3233), integer(6), integer(1925), integer(9), integer(2876)},
			func(a []*big.Int) (*big.Int, error) { return rsactf.CommonModulus(a[0], a[1], a[2], a[3], a[4]) }},
		{"factor recovery", []*big.Int{integer(11413), integer(7), integer(101), integer(11)},
			func(a []*big.Int) (*big.Int, error) {
				return rsactf.CommonModulus(a[0], a[1], new(big.Int).Exp(a[2], a[1], a[0]), a[3], new(big.Int).Exp(a[2], a[3], a[0]))
			}},
		{"repeated squaring", []*big.Int{integer(11413), integer(1867), integer(3)},
			func(a []*big.Int) (*big.Int, error) { return rsactf.FactorFromCRTExponent(a[0], a[1], a[2], 32) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := make([]*big.Int, len(tc.args))
			for i, arg := range tc.args {
				before[i] = new(big.Int).Set(arg)
			}
			got, err := tc.run(tc.args)
			if err != nil {
				t.Fatal(err)
			}
			got.SetInt64(0)
			for i, arg := range tc.args {
				if arg.Cmp(before[i]) != 0 {
					t.Fatalf("argument %d changed", i)
				}
			}
		})
	}
}

func TestCommonModulusSmallSemiprimes(t *testing.T) {
	for _, pair := range [][2]int64{{3, 5}, {5, 7}, {7, 11}} {
		n := integer(pair[0] * pair[1])
		for e1 := int64(1); e1 <= 12; e1++ {
			for e2 := int64(1); e2 <= 12; e2++ {
				for m := int64(0); m < n.Int64(); m++ {
					c1, c2 := integer(1), integer(1)
					// Build observations independently by repeated multiplication.
					for i := int64(0); i < e1; i++ {
						c1.SetInt64(c1.Int64() * m % n.Int64())
					}
					for i := int64(0); i < e2; i++ {
						c2.SetInt64(c2.Int64() * m % n.Int64())
					}
					got, err := rsactf.CommonModulus(n, integer(e1), c1, integer(e2), c2)
					if errors.Is(err, rsactf.ErrNoResult) {
						continue
					}
					if err != nil || got == nil || got.Sign() < 0 || got.Cmp(n) >= 0 {
						t.Fatalf("n=%v e1=%d e2=%d m=%d: (%v, %v)", n, e1, e2, m, got, err)
					}
					for _, check := range [][2]int64{{e1, c1.Int64()}, {e2, c2.Int64()}} {
						value := int64(1)
						for i := int64(0); i < check[0]; i++ {
							value = value * got.Int64() % n.Int64()
						}
						if value != check[1] {
							t.Fatalf("n=%v e1=%d e2=%d m=%d: recovered %v fails observation", n, e1, e2, m, got)
						}
					}
				}
			}
		}
	}
}
