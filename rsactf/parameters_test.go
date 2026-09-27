package rsactf_test

import (
	"math/big"
	"testing"

	"github.com/wave4y/cryptoutils/rsactf"
)

func TestCompletePrivateParameters(t *testing.T) {
	p, q, e := integer(61), integer(53), integer(17)
	key, err := rsactf.CompletePrivateParameters(p, q, e)
	if err != nil {
		t.Fatal(err)
	}
	for name, pair := range map[string][2]*big.Int{
		"n": {key.N, integer(3233)}, "e": {key.E, e},
		"p": {key.P, p}, "q": {key.Q, q},
		"phi": {key.Phi, integer(3120)}, "lambda": {key.Lambda, integer(780)},
		"d": {key.D, integer(413)}, "dp": {key.DP, integer(53)}, "dq": {key.DQ, integer(49)},
	} {
		if pair[0].Cmp(pair[1]) != 0 {
			t.Errorf("%s = %s, want %s", name, pair[0], pair[1])
		}
	}
	// Include non-units and zero: a completed key must decrypt every residue.
	for m := int64(0); m < 3233; m++ {
		cipher, err := rsactf.EncryptRaw(key.N, key.E, integer(m))
		if err != nil {
			t.Fatal(err)
		}
		plain, err := rsactf.DecryptRaw(key.N, key.D, cipher)
		requireInteger(t, plain, err, m)
		plain, err = rsactf.DecryptCRT(key.P, key.Q, key.DP, key.DQ, cipher)
		requireInteger(t, plain, err, m)
	}
	// Large exponents and reversed factors are valid as well.
	largeE := new(big.Int).Add(new(big.Int).Lsh(integer(780), 100), e)
	other, err := rsactf.CompletePrivateParameters(q, p, largeE)
	if err != nil || other.E.Cmp(largeE) != 0 || other.D.Cmp(key.D) != 0 || other.DP.Cmp(key.DQ) != 0 {
		t.Fatalf("large exponent/reversed factors: %v, %v", other, err)
	}
}

func TestPrivateExponent(t *testing.T) {
	for _, tc := range []struct{ e, totient, d int64 }{
		{17, 3120, 2753}, {17, 780, 413}, {5, 4, 1}, {3, 2, 1},
	} {
		e, totient := integer(tc.e), integer(tc.totient)
		d, err := rsactf.PrivateExponent(e, totient)
		requireInteger(t, d, err, tc.d)
		if e.Int64() != tc.e || totient.Int64() != tc.totient {
			t.Fatal("mutated exponent or totient")
		}
	}
	_, err := rsactf.PrivateExponent(integer(12), integer(780))
	requireError(t, err, rsactf.ErrNoResult)
	for _, invalid := range []*big.Int{nil, integer(-1), integer(0), integer(1)} {
		_, err = rsactf.PrivateExponent(invalid, integer(780))
		requireError(t, err, rsactf.ErrInvalidInput)
		_, err = rsactf.PrivateExponent(integer(17), invalid)
		requireError(t, err, rsactf.ErrInvalidInput)
	}
}

func TestCompletePrivateParametersRejectsInvalidInputs(t *testing.T) {
	for _, invalid := range []*big.Int{nil, integer(-1), integer(0), integer(1), integer(2), integer(4), integer(9), integer(561)} {
		_, err := rsactf.CompletePrivateParameters(invalid, integer(53), integer(17))
		requireError(t, err, rsactf.ErrInvalidInput)
		_, err = rsactf.CompletePrivateParameters(integer(53), invalid, integer(17))
		requireError(t, err, rsactf.ErrInvalidInput)
	}
	for _, invalid := range []*big.Int{nil, integer(-1), integer(0), integer(1)} {
		_, err := rsactf.CompletePrivateParameters(integer(61), integer(53), invalid)
		requireError(t, err, rsactf.ErrInvalidInput)
	}
	_, err := rsactf.CompletePrivateParameters(integer(53), integer(53), integer(17))
	requireError(t, err, rsactf.ErrInvalidInput)
	_, err = rsactf.CompletePrivateParameters(integer(61), integer(53), integer(3))
	requireError(t, err, rsactf.ErrNoResult)
}

func TestCompletePrivateParametersDoesNotAlias(t *testing.T) {
	fields := func(key *rsactf.PrivateParameters) []*big.Int {
		return []*big.Int{key.N, key.E, key.D, key.P, key.Q, key.DP, key.DQ, key.Phi, key.Lambda}
	}
	for target := 0; target < 9; target++ {
		p, q, e := integer(61), integer(53), integer(17)
		key, err := rsactf.CompletePrivateParameters(p, q, e)
		if err != nil {
			t.Fatal(err)
		}
		values := fields(key)
		want := make([]*big.Int, len(values))
		for i, value := range values {
			want[i] = new(big.Int).Set(value)
			for j := 0; j < i; j++ {
				if value == values[j] {
					t.Fatal("output pointer alias")
				}
			}
		}
		values[target].SetInt64(999)
		for i, value := range values {
			if i != target && value.Cmp(want[i]) != 0 {
				t.Fatalf("mutating field %d affected field %d", target, i)
			}
		}
		if p.Int64() != 61 || q.Int64() != 53 || e.Int64() != 17 {
			t.Fatal("output aliases an input")
		}
	}
}
