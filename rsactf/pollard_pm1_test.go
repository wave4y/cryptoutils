package rsactf

import (
	"context"
	"errors"
	"math/big"
	"reflect"
	"testing"
)

func TestPollardPMinusOneFactors(t *testing.T) {
	for _, tc := range []struct {
		name     string
		n        int64
		bound    uint64
		attempts uint64
	}{
		{"official small key", 31 * 83, 10000, 1},
		{"power of two smoothness", 257 * 1019, 256, 1},
		{"intermediate power", 17 * 257, 256, 1},
		{"maximal bound", 17 * 257, ^uint64(0), 1},
		{"base shares factor", 2 * 19, 2, 1},
		{"third consecutive base", 5 * 13, 2, 3},
		{"square modulus", 7 * 7, 3, 1},
		{"three prime factors", 3 * 5 * 7, 2, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := big.NewInt(tc.n)
			factor, err := PollardPMinusOne(n, tc.bound, tc.attempts)
			if err != nil || factor == nil || factor.Cmp(big.NewInt(1)) <= 0 || factor.Cmp(n) >= 0 || new(big.Int).Mod(n, factor).Sign() != 0 {
				t.Fatalf("got factor %v, error %v for n=%v", factor, err, n)
			}
			if n.Int64() != tc.n {
				t.Fatal("modified input")
			}
			factor.SetInt64(0)
			if n.Int64() != tc.n {
				t.Fatal("returned factor aliases input")
			}
		})
	}
}

func TestPollardPMinusOneBudgets(t *testing.T) {
	for _, tc := range []struct {
		n        int64
		bound    uint64
		attempts uint64
	}{
		{2573, 100, 0},
		{38, 100, 0},
		{2573, 2, 1},
		{65, 2, 2},
		{2, 2, ^uint64(0)},
		{3, 2, ^uint64(0)},
		{1019, 2000, 3},
	} {
		factor, err := PollardPMinusOne(big.NewInt(tc.n), tc.bound, tc.attempts)
		if factor != nil || !errors.Is(err, ErrNoResult) {
			t.Errorf("n=%d, bound=%d, attempts=%d: got %v, %v", tc.n, tc.bound, tc.attempts, factor, err)
		}
	}
}

func TestPollardPMinusOneValidation(t *testing.T) {
	for _, n := range []*big.Int{nil, big.NewInt(-1), big.NewInt(0), big.NewInt(1)} {
		if factor, err := PollardPMinusOne(n, 2, 1); factor != nil || !errors.Is(err, ErrInvalidInput) {
			t.Errorf("n=%v: got %v, %v", n, factor, err)
		}
	}
	for _, bound := range []uint64{0, 1} {
		if factor, err := PollardPMinusOne(big.NewInt(15), bound, 1); factor != nil || !errors.Is(err, ErrInvalidInput) {
			t.Errorf("bound=%d: got %v, %v", bound, factor, err)
		}
	}
	if factor, err := PollardPMinusOneContext(nil, big.NewInt(15), 2, 1); factor != nil || !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil context: got %v, %v", factor, err)
	}
}

// Cancel after a deterministic number of checks rather than depending on
// machine speed to interrupt the sieve or an exponentiation loop.
type pollardCancelContext struct {
	context.Context
	cancel    context.CancelFunc
	remaining int
}

func (ctx *pollardCancelContext) Err() error {
	ctx.remaining--
	if ctx.remaining == 0 {
		ctx.cancel()
	}
	return ctx.Context.Err()
}

func TestPollardPMinusOneCancellation(t *testing.T) {
	for _, after := range []int{1, 8, 100, 1000} {
		ctx, cancel := context.WithCancel(context.Background())
		counted := &pollardCancelContext{Context: ctx, cancel: cancel, remaining: after}
		factor, err := PollardPMinusOneContext(counted, big.NewInt(1000000007), ^uint64(0), 1)
		cancel()
		if factor != nil || !errors.Is(err, context.Canceled) {
			t.Errorf("cancel after %d checks: got %v, %v", after, factor, err)
		}
	}
}

func TestPollardPrimeSieve(t *testing.T) {
	for _, limit := range []uint64{0, 1, 2, 3, 4, 32768, 32769, 65536, 100000} {
		var want, got []uint64
		// Independent whole-range sieve is small enough for these test
		// bounds and checks both sides of the implementation's segments.
		composite := make([]bool, int(limit+1))
		for candidate := uint64(2); candidate <= limit; candidate++ {
			if !composite[candidate] {
				want = append(want, candidate)
				for multiple := candidate * candidate; multiple <= limit; multiple += candidate {
					composite[multiple] = true
				}
			}
		}
		stopped, err := visitPollardPrimes(context.Background(), limit, func(prime uint64) (bool, error) {
			got = append(got, prime)
			return false, nil
		})
		if stopped || err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("limit=%d: stopped=%v, error=%v, got %d primes, want %d", limit, stopped, err, len(got), len(want))
		}
	}
}

func TestPollardPrimeSieveHugeBoundEarlyStop(t *testing.T) {
	var got []uint64
	stopped, err := visitPollardPrimes(context.Background(), ^uint64(0), func(prime uint64) (bool, error) {
		got = append(got, prime)
		return len(got) == 6, nil
	})
	if !stopped || err != nil || !reflect.DeepEqual(got, []uint64{2, 3, 5, 7, 11, 13}) {
		t.Fatalf("got %v, stopped=%v, error=%v", got, stopped, err)
	}
}

func TestPollardPMinusOneRsaCtfToolSmallQ(t *testing.T) {
	// Numerical public challenge data from RsaCtfTool commit
	// fb8532a54227b61f99277bd09483a3570c02c8f8, examples/small_q.pub and
	// examples/small_q.cipher. The fixed plaintext is also re-encrypted.
	const nText = "8597656297860545107091403497608238810415884857788354623649545462584626186357491015183008751788834205126626170046660764709588721169432974804650110624299531971774114543254422558416305578835040900745856782965785268333750404184841766134544089627917308591465828618442384534122739386366913053748919149466237339278512341"
	const cText = "7724116964798451344200701644254163532428558646414732867051128820902145042132876123484277156215281121590079351896189128372583137478445868285029472154619213166260064233992754923977914003320835384833101291989200455373651185161925071400349299638272536552110838496809827580866502214472025776993110955644986956443815700"
	n, ok := new(big.Int).SetString(nText, 10)
	if !ok {
		t.Fatal("invalid modulus fixture")
	}
	c, ok := new(big.Int).SetString(cText, 10)
	if !ok {
		t.Fatal("invalid ciphertext fixture")
	}
	p, err := PollardPMinusOne(n, 10000, 3)
	if err != nil || p == nil || p.Cmp(big.NewInt(1)) <= 0 || p.Cmp(n) >= 0 || new(big.Int).Mod(n, p).Sign() != 0 {
		t.Fatalf("factorization: got %v, %v", p, err)
	}
	q := new(big.Int).Quo(n, p)
	if !p.ProbablyPrime(32) || !q.ProbablyPrime(32) {
		t.Fatal("recovered factors are not prime")
	}
	phi := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))
	e := big.NewInt(65537)
	d := new(big.Int).ModInverse(e, phi)
	if d == nil {
		t.Fatal("no private exponent")
	}
	m, err := DecryptRaw(n, d, c)
	if err != nil || string(m.Bytes()) != "hQdK+dKleMJqth/dofWyFaiWp3PW7jil" {
		t.Fatalf("unexpected plaintext %v, %v", m, err)
	}
	if new(big.Int).Exp(m, e, n).Cmp(c) != 0 {
		t.Fatal("ciphertext mismatch")
	}
}
