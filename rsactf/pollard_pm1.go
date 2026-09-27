package rsactf

import (
	"context"
	"math"
	"math/big"
)

// PollardPMinusOne searches for a proper factor of n using stage 1 of
// Pollard's p-1 method with smoothness bound >= 2. It tries at most attempts
// consecutive bases starting at 2 and smaller than n; zero attempts performs
// no search. A factor need not be prime. ErrNoResult means that the chosen
// bases and bound did not find a factor, not that n is prime. Stage 2 is not
// implemented. Inputs are never modified.
// Its NoResultError reports ReasonSearchExhausted after all bases in [2,n)
// were tried at the supplied bound, or ReasonBudgetExhausted when the attempt
// limit stopped the search. Zero attempts always reports ReasonBudgetExhausted.
func PollardPMinusOne(n *big.Int, bound, attempts uint64) (*big.Int, error) {
	return PollardPMinusOneContext(context.Background(), n, bound, attempts)
}

// PollardPMinusOneContext is PollardPMinusOne with cooperative cancellation
// during prime generation and between integer operations. A nil context is
// invalid; cancellation returns ctx.Err(). Prime generation uses bounded
// segment storage even for very large bounds, but the running time still
// grows with the bound. One math/big operation cannot be interrupted.
func PollardPMinusOneContext(ctx context.Context, n *big.Int, bound, attempts uint64) (*big.Int, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if !validModulus(n) || bound < 2 {
		return nil, ErrInvalidInput
	}
	if attempts == 0 {
		return nil, noResult("PollardPMinusOne", ReasonBudgetExhausted)
	}
	one, base := big.NewInt(1), big.NewInt(2)
	gcd, delta, exponent := new(big.Int), new(big.Int), new(big.Int)
	for attempt := uint64(0); attempt < attempts && base.Cmp(n) < 0; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		gcd.GCD(nil, nil, base, n)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if gcd.Cmp(one) > 0 {
			return new(big.Int).Set(gcd), nil
		}
		a := new(big.Int).Set(base)
		var factor *big.Int
		_, err := visitPollardPrimes(ctx, bound, func(prime uint64) (bool, error) {
			// The division guard prevents overflow when bound is MaxUint64.
			power := prime
			for power <= bound/prime {
				power *= prime
			}
			previous := new(big.Int).Set(a)
			a.Exp(a, exponent.SetUint64(power), n)
			if err := ctx.Err(); err != nil {
				return false, err
			}
			gcd.GCD(nil, nil, delta.Sub(a, one), n)
			if gcd.Cmp(one) == 0 {
				return false, nil
			}
			if gcd.Cmp(n) < 0 {
				factor = new(big.Int).Set(gcd)
				return true, nil
			}
			// A full prime power can make both factors divide a-1 at
			// once. Replay its individual prime steps before restarting
			// the base, retaining a factor exposed at an earlier step.
			exponent.SetUint64(prime)
			for remaining := power; remaining > 1; remaining /= prime {
				if err := ctx.Err(); err != nil {
					return false, err
				}
				previous.Exp(previous, exponent, n)
				if err := ctx.Err(); err != nil {
					return false, err
				}
				gcd.GCD(nil, nil, delta.Sub(previous, one), n)
				if gcd.Cmp(one) > 0 {
					if gcd.Cmp(n) < 0 {
						factor = new(big.Int).Set(gcd)
					}
					break
				}
			}
			return true, nil
		})
		if err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if factor != nil {
			return factor, nil
		}
		base.Add(base, one)
	}
	if base.Cmp(n) >= 0 {
		return nil, noResult("PollardPMinusOne", ReasonSearchExhausted)
	}
	return nil, noResult("PollardPMinusOne", ReasonBudgetExhausted)
}

// visitPollardPrimes visits primes in ascending order, stopping when visit
// returns true. Segments have fixed size. Their base primes are generated
// with the same bounded sieve rather than allocating sqrt(limit) entries;
// at most a few recursive levels are needed for a uint64 limit.
func visitPollardPrimes(ctx context.Context, limit uint64, visit func(uint64) (bool, error)) (bool, error) {
	const segmentSize uint64 = 32768
	if limit < 2 {
		return false, nil
	}
	for low := uint64(2); ; {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		high := limit
		if limit-low >= segmentSize {
			high = low + segmentSize - 1
		}
		composite := make([]bool, int(high-low+1))
		mark := func(prime uint64) (bool, error) {
			start := low
			if remainder := low % prime; remainder != 0 {
				difference := prime - remainder
				if difference > high-low {
					return false, nil
				}
				start += difference
			}
			if square := prime * prime; start < square {
				start = square
			}
			for multiple := start; multiple <= high; {
				if err := ctx.Err(); err != nil {
					return false, err
				}
				composite[int(multiple-low)] = true
				if high-multiple < prime {
					break
				}
				multiple += prime
			}
			return false, nil
		}
		if high > segmentSize {
			// Float sqrt is only an estimate. Division-based corrections
			// keep the exact floor root without squaring past uint64.
			root := uint64(math.Sqrt(float64(high)))
			for root > high/root {
				root--
			}
			for root+1 <= high/(root+1) {
				root++
			}
			if _, err := visitPollardPrimes(ctx, root, mark); err != nil {
				return false, err
			}
		}
		for candidate := low; ; candidate++ {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			if !composite[int(candidate-low)] {
				if high <= segmentSize && candidate <= high/candidate {
					if _, err := mark(candidate); err != nil {
						return false, err
					}
				}
				if stop, err := visit(candidate); stop || err != nil {
					return stop, err
				}
			}
			if candidate == high {
				break
			}
		}
		if high == limit {
			return false, nil
		}
		low = high + 1
	}
}
