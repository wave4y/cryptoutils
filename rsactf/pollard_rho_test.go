package rsactf_test

import (
	"context"
	"errors"
	"math"
	"math/big"
	"testing"

	"github.com/wave4y/cryptoutils/rsactf"
)

func TestPollardRhoFactors(t *testing.T) {
	for _, value := range []int64{4, 6, 9, 15, 25, 49, 77, 81, 105, 121, 1022117} {
		n := big.NewInt(value)
		before := new(big.Int).Set(n)
		factor, err := rsactf.PollardRho(n, 10000, 16)
		requireFactor(t, n, factor, err)
		if n.Cmp(before) != 0 {
			t.Fatalf("input changed for %d", value)
		}
		again, err := rsactf.PollardRho(n, 10000, 16)
		if err != nil || again.Cmp(factor) != 0 {
			t.Fatalf("search is not reproducible for %d: %v %v", value, again, err)
		}
		factor.SetInt64(0)
		if n.Cmp(before) != 0 || again.Sign() <= 0 {
			t.Fatalf("result aliases input or another result for %d", value)
		}
	}
}

func TestPollardRhoSmallCompositeDomain(t *testing.T) {
	// Trial division supplies an independent small-domain oracle, including
	// squares, prime powers, and products of more than two primes.
	for value := int64(4); value < 1000; value++ {
		composite := false
		for divisor := int64(2); divisor*divisor <= value; divisor++ {
			if value%divisor == 0 {
				composite = true
				break
			}
		}
		if !composite {
			continue
		}
		n := big.NewInt(value)
		factor, err := rsactf.PollardRho(n, 10000, 16)
		requireFactor(t, n, factor, err)
	}
}

func TestPollardRhoBudgets(t *testing.T) {
	for _, n := range []int64{2, 3, 7, 17, 101, 1009} {
		factor, err := rsactf.PollardRho(big.NewInt(n), 10000, 16)
		if factor != nil || !errors.Is(err, rsactf.ErrNoResult) {
			t.Fatalf("prime %d: got %v, %v", n, factor, err)
		}
	}
	for _, tc := range []struct {
		n               int64
		steps, attempts uint64
	}{
		{4, 0, 1}, {4, 1, 0}, {15, 0, 16}, {15, 10, 0},
		{15, 1, 16},
		// For n=25, the first walk collides modulo n. Its GCD batch
		// requires a replay, consuming seven evaluations in total.
		// The second walk needs two more evaluations to find factor 5.
		{25, 6, 16}, {25, 7, 16}, {25, 8, 16},
		{25, 10000, 1},
		{25, 8, math.MaxUint64},
		{3, math.MaxUint64, 1},
	} {
		factor, err := rsactf.PollardRho(big.NewInt(tc.n), tc.steps, tc.attempts)
		if factor != nil || !errors.Is(err, rsactf.ErrNoResult) {
			t.Fatalf("n=%d steps=%d attempts=%d: got %v, %v", tc.n, tc.steps, tc.attempts, factor, err)
		}
	}
	for _, tc := range []struct {
		n, want         int64
		steps, attempts uint64
	}{
		{4, 2, 1, 1}, {15, 3, 2, 1}, {25, 5, 9, 2},
		{25, 5, math.MaxUint64, math.MaxUint64},
	} {
		factor, err := rsactf.PollardRho(big.NewInt(tc.n), tc.steps, tc.attempts)
		requireInteger(t, factor, err, tc.want)
	}
}

func TestPollardRhoInvalidInput(t *testing.T) {
	for _, n := range []*big.Int{nil, big.NewInt(-1), big.NewInt(0), big.NewInt(1)} {
		factor, err := rsactf.PollardRho(n, 100, 16)
		if factor != nil || !errors.Is(err, rsactf.ErrInvalidInput) {
			t.Fatalf("n=%v: got %v, %v", n, factor, err)
		}
	}
	factor, err := rsactf.PollardRhoContext(nil, big.NewInt(15), 100, 16)
	if factor != nil || !errors.Is(err, rsactf.ErrInvalidInput) {
		t.Fatalf("nil context: got %v, %v", factor, err)
	}
}

type rhoCancelContext struct {
	context.Context
	calls int
}

func (ctx *rhoCancelContext) Err() error {
	ctx.calls++
	if ctx.calls >= 5 {
		return context.Canceled
	}
	return nil
}

func TestPollardRhoCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, n := range []int64{4, 15} {
		factor, err := rsactf.PollardRhoContext(ctx, big.NewInt(n), 100, 16)
		if factor != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("pre-canceled n=%d: got %v, %v", n, factor, err)
		}
	}
	// Cancel deterministically after entering the polynomial walk. This
	// checks cancellation inside work without timing-sensitive sleeps.
	during := &rhoCancelContext{Context: context.Background()}
	factor, err := rsactf.PollardRhoContext(during, big.NewInt(1022117), math.MaxUint64, 16)
	if factor != nil || !errors.Is(err, context.Canceled) || during.calls != 5 {
		t.Fatalf("in-progress cancellation: got %v, %v after %d checks", factor, err, during.calls)
	}
}

func TestPollardRhoRsaCtfToolSmallQ(t *testing.T) {
	// Public numerical challenge data from RsaCtfTool at commit
	// fb8532a54227b61f99277bd09483a3570c02c8f8, examples/small_q.pub
	// and examples/small_q.cipher. Recovery uses only n, not a known factor.
	// https://github.com/RsaCtfTool/RsaCtfTool/tree/fb8532a54227b61f99277bd09483a3570c02c8f8/examples
	n, ok := new(big.Int).SetString("8597656297860545107091403497608238810415884857788354623649545462584626186357491015183008751788834205126626170046660764709588721169432974804650110624299531971774114543254422558416305578835040900745856782965785268333750404184841766134544089627917308591465828618442384534122739386366913053748919149466237339278512341", 10)
	if !ok {
		t.Fatal("invalid modulus fixture")
	}
	c, ok := new(big.Int).SetString("7724116964798451344200701644254163532428558646414732867051128820902145042132876123484277156215281121590079351896189128372583137478445868285029472154619213166260064233992754923977914003320835384833101291989200455373651185161925071400349299638272536552110838496809827580866502214472025776993110955644986956443815700", 10)
	if !ok {
		t.Fatal("invalid ciphertext fixture")
	}
	p, err := rsactf.PollardRho(n, 10000, 16)
	requireFactor(t, n, p, err)
	q := new(big.Int).Quo(n, p)
	key, err := rsactf.CompletePrivateParameters(p, q, big.NewInt(65537))
	if err != nil {
		t.Fatal(err)
	}
	m, err := rsactf.DecryptRaw(n, key.D, c)
	if err != nil {
		t.Fatal(err)
	}
	if string(m.Bytes()) != "hQdK+dKleMJqth/dofWyFaiWp3PW7jil" || new(big.Int).Exp(m, key.E, n).Cmp(c) != 0 {
		t.Fatalf("unexpected or unverifiable plaintext: %x", m.Bytes())
	}
}
