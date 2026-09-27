package rsactf

import (
	"context"
	"math/big"
)

// PollardRho searches for a proper factor of n > 1 using deterministic Brent
// walks. maxSteps is the total number of polynomial evaluations across all
// walks, including recovery after an unsuccessful GCD batch. attempts limits
// the number of walks. Either budget being zero performs no search. With
// positive budgets, even n > 2 immediately returns 2. The returned factor may
// be composite. Its NoResultError reports ReasonBudgetExhausted when either
// budget stops the search, which does not prove that n is prime. With positive
// budgets n=2 reports ReasonSearchExhausted because it has no proper factor.
// The input is preserved and the returned factor does not alias it.
func PollardRho(n *big.Int, maxSteps, attempts uint64) (*big.Int, error) {
	return PollardRhoContext(context.Background(), n, maxSteps, attempts)
}

// PollardRhoContext is PollardRho with cooperative cancellation at every
// polynomial evaluation and between GCD operations. It cannot interrupt one
// math/big operation. A nil context is invalid; cancellation returns ctx.Err().
func PollardRhoContext(ctx context.Context, n *big.Int, maxSteps, attempts uint64) (*big.Int, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if !validModulus(n) {
		return nil, ErrInvalidInput
	}
	if maxSteps == 0 || attempts == 0 {
		return nil, noResult("PollardRho", ReasonBudgetExhausted)
	}
	one, two := big.NewInt(1), big.NewInt(2)
	if n.Bit(0) == 0 {
		if n.Cmp(two) > 0 {
			return two, nil
		}
		return nil, noResult("PollardRho", ReasonSearchExhausted)
	}

	remaining := maxSteps
	nMinusOne := new(big.Int).Sub(n, one)
	c, y, x, saved := new(big.Int), new(big.Int), new(big.Int), new(big.Int)
	product, difference, factor := new(big.Int), new(big.Int), new(big.Int)
	advance := func(value *big.Int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if remaining == 0 {
			return noResult("PollardRho", ReasonBudgetExhausted)
		}
		value.Mul(value, value)
		value.Add(value, c)
		value.Mod(value, n)
		remaining--
		return ctx.Err()
	}
	properFactor := func() bool {
		return factor.Cmp(one) > 0 && factor.Cmp(n) < 0 &&
			new(big.Int).Mod(n, factor).Sign() == 0
	}

	for attempt := uint64(0); attempt < attempts && remaining > 0; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// Do additions as big integers so even MaxUint64 budgets cannot
		// overflow the deterministic seed or polynomial constant.
		c.SetUint64(attempt)
		c.Mod(c, nMinusOne)
		c.Add(c, one)
		y.SetUint64(attempt)
		y.Add(y, two)
		y.Mod(y, n)

		restart := false
		for span := uint64(1); remaining > 0 && !restart; {
			x.Set(y)
			for step := uint64(0); step < span; step++ {
				if err := advance(y); err != nil {
					return nil, err
				}
			}
			for offset := uint64(0); offset < span && remaining > 0; {
				batch := span - offset
				if batch > 64 {
					batch = 64
				}
				if batch > remaining {
					batch = remaining
				}
				saved.Set(y)
				product.SetInt64(1)
				for step := uint64(0); step < batch; step++ {
					if err := advance(y); err != nil {
						return nil, err
					}
					difference.Sub(x, y)
					product.Mul(product, difference)
					product.Mod(product, n)
				}
				factor.GCD(nil, nil, product, n)
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				if properFactor() {
					return new(big.Int).Set(factor), nil
				}
				if factor.Cmp(n) == 0 {
					// A batch may contain collisions for different factors.
					// Replay it one step at a time; replay also consumes the
					// shared evaluation budget.
					for step := uint64(0); step < batch; step++ {
						if err := advance(saved); err != nil {
							return nil, err
						}
						difference.Sub(x, saved)
						factor.GCD(nil, nil, difference, n)
						if err := ctx.Err(); err != nil {
							return nil, err
						}
						if properFactor() {
							return new(big.Int).Set(factor), nil
						}
						if factor.Cmp(n) == 0 {
							break
						}
					}
					restart = true
					break
				}
				offset += batch
			}
			// Bound the next span by the remaining budget before doubling,
			// avoiding both uint64 overflow and an oversized advance phase.
			if span > remaining/2 {
				span = remaining
			} else {
				span *= 2
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, noResult("PollardRho", ReasonBudgetExhausted)
}
