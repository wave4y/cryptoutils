package rsactf

import "math/big"

// LowExponent searches c+k*n for an exact e-th power, for 0 <= k <= maxK.
// It supports 2 <= e <= 64, n > 1, and canonical ciphertexts 0 <= c < n.
// Every candidate is checked by re-encryption. ErrNoResult means that no
// canonical plaintext was found within this inclusive search budget.
func LowExponent(n, e, c *big.Int, maxK uint64) (*big.Int, error) {
	if !validModulus(n) || !validExponent(e) || !validResidue(c, n) ||
		!e.IsUint64() || e.Uint64() < 2 || e.Uint64() > 64 {
		return nil, ErrInvalidInput
	}
	degree := uint(e.Uint64())
	x := new(big.Int).Set(c)
	for k := uint64(0); ; k++ {
		m, exact, err := IntegerRoot(x, degree)
		if err != nil {
			return nil, err
		}
		if exact && verifiedPlaintext(m, n, e, c) {
			return m, nil
		}
		// Stop before incrementing, including when maxK is MaxUint64.
		if k == maxK || m.Cmp(n) >= 0 {
			return nil, ErrNoResult
		}
		x.Add(x, n)
	}
}

// Broadcast recovers the same unpadded message encrypted with exponent e
// under at least two pairwise coprime moduli. It supports 2 <= e <= 64 and
// canonical ciphertexts. Recovery requires m^e < the product of the moduli;
// e ciphertexts usually suffice, but fewer may work for a small message.
// A recovered message is re-encrypted under every supplied public key.
func Broadcast(moduli, ciphertexts []*big.Int, e uint) (*big.Int, error) {
	if e < 2 || e > 64 {
		return nil, ErrInvalidInput
	}
	x, err := CRT(moduli, ciphertexts)
	if err != nil {
		return nil, err
	}
	m, exact, err := IntegerRoot(x, e)
	if err != nil {
		return nil, err
	}
	if !exact {
		return nil, ErrNoResult
	}
	exponent := new(big.Int).SetUint64(uint64(e))
	for i, modulus := range moduli {
		if !verifiedPlaintext(m, modulus, exponent, ciphertexts[i]) {
			return nil, ErrNoResult
		}
	}
	return m, nil
}

// CommonModulus recovers an unpadded message encrypted modulo n with
// positive exponents e1 and e2, verifying every result against both canonical
// ciphertexts. For g=gcd(e1,e2)>1, recovery uses an exact integer g-th root
// and requires m^g < n. If a ciphertext exposes a factor, recovery is also
// attempted for a product of two distinct probable primes when either
// exponent is invertible modulo lambda(n). Other cases return ErrNoResult;
// this does not prove that the ciphertext pair has no common plaintext.
func CommonModulus(n, e1, c1, e2, c2 *big.Int) (*big.Int, error) {
	if !validModulus(n) || !validExponent(e1) || !validExponent(e2) ||
		!validResidue(c1, n) || !validResidue(c2, n) {
		return nil, ErrInvalidInput
	}
	if c1.Sign() == 0 && c2.Sign() == 0 {
		return new(big.Int), nil
	}
	one := big.NewInt(1)
	verify := func(m *big.Int) bool {
		return verifiedPlaintext(m, n, e1, c1) && verifiedPlaintext(m, n, e2, c2)
	}
	a, b := new(big.Int), new(big.Int)
	g := new(big.Int).GCD(a, b, e1, e2)
	x := new(big.Int).Exp(c1, a, n)
	y := new(big.Int).Exp(c2, b, n)
	if x != nil && y != nil {
		m := new(big.Int).Mod(new(big.Int).Mul(x, y), n)
		if g.Cmp(one) == 0 || m.Cmp(one) <= 0 {
			if verify(m) {
				return m, nil
			}
		} else if g.Cmp(new(big.Int).SetUint64(uint64(m.BitLen()))) < 0 {
			// For x > 1 and degree >= bitlen(x), the floor root is 1
			// and cannot be exact. This bound also makes conversion
			// to uint safe.
			m, exact, err := IntegerRoot(m, uint(g.Uint64()))
			if err != nil {
				return nil, err
			}
			if exact && verify(m) {
				return m, nil
			}
		}
	}
	// Try the original exponent combination first: it also covers some
	// square and multi-prime moduli, for example an exponent of one.
	// Only this fallback assumes a product of two distinct primes.
	for _, c := range []*big.Int{c1, c2} {
		p := new(big.Int).GCD(nil, nil, c, n)
		if p.Cmp(one) == 0 {
			continue
		}
		if p.Cmp(n) == 0 {
			// A zero ciphertext reveals no proper factor by itself.
			continue
		}
		q := new(big.Int).Quo(n, p)
		if p.Cmp(q) == 0 || !p.ProbablyPrime(32) || !q.ProbablyPrime(32) {
			return nil, ErrNoResult
		}
		pm1, qm1 := new(big.Int).Sub(p, one), new(big.Int).Sub(q, one)
		lambda := new(big.Int).GCD(nil, nil, pm1, qm1)
		lambda.Quo(pm1, lambda)
		lambda.Mul(lambda, qm1)
		for _, pair := range [][2]*big.Int{{e1, c1}, {e2, c2}} {
			d := new(big.Int).ModInverse(pair[0], lambda)
			if d != nil {
				m := new(big.Int).Exp(pair[1], d, n)
				if verify(m) {
					return m, nil
				}
			}
		}
		return nil, ErrNoResult
	}
	return nil, ErrNoResult
}

// SharedFactor returns gcd(n1,n2) only when it is a proper nontrivial factor
// of both moduli. Coprime, identical, or wholly dividing moduli return
// ErrNoResult. Both moduli must be greater than one.
func SharedFactor(n1, n2 *big.Int) (*big.Int, error) {
	if !validModulus(n1) || !validModulus(n2) {
		return nil, ErrInvalidInput
	}
	p := new(big.Int).GCD(nil, nil, n1, n2)
	if p.Cmp(big.NewInt(1)) <= 0 || p.Cmp(n1) >= 0 || p.Cmp(n2) >= 0 {
		return nil, ErrNoResult
	}
	return p, nil
}

// Fermat finds a nontrivial factor of n by searching for n=a^2-b^2. For
// odd n, it examines at most maxSteps consecutive candidates starting at
// a=ceil(sqrt(n)); maxSteps=0 performs no search. Even n > 2 immediately
// returns 2 regardless of the budget. ErrNoResult does not prove primality.
func Fermat(n *big.Int, maxSteps uint64) (*big.Int, error) {
	if !validModulus(n) {
		return nil, ErrInvalidInput
	}
	if n.Bit(0) == 0 {
		if n.Cmp(big.NewInt(2)) > 0 {
			return big.NewInt(2), nil
		}
		return nil, ErrNoResult
	}
	a := new(big.Int).Sqrt(n)
	bSquared := new(big.Int).Sub(new(big.Int).Mul(a, a), n)
	if bSquared.Sign() < 0 {
		a.Add(a, big.NewInt(1))
		bSquared.Sub(new(big.Int).Mul(a, a), n)
	}
	one := big.NewInt(1)
	for step := uint64(0); step < maxSteps; step++ {
		b := new(big.Int).Sqrt(bSquared)
		if new(big.Int).Mul(b, b).Cmp(bSquared) == 0 {
			p := new(big.Int).Sub(a, b)
			if p.Cmp(one) > 0 && p.Cmp(n) < 0 {
				return p, nil
			}
			// Reaching 1*n exhausts the possible nontrivial factorizations.
			return nil, ErrNoResult
		}
		// (a+1)^2-n = (a^2-n)+2*a+1.
		bSquared.Add(bSquared, new(big.Int).Lsh(a, 1))
		bSquared.Add(bSquared, one)
		a.Add(a, one)
	}
	return nil, ErrNoResult
}

// FactorFromPhi recovers a nontrivial factor using phi=(p-1)*(q-1) and
// n=p*q, the relation for two distinct primes. It requires 0 < phi < n
// and checks that the recovered factors are distinct probable primes.
// An inconsistent phi or a modulus outside that relation yields ErrNoResult.
// This is not a general factorization method for multi-prime or square RSA.
func FactorFromPhi(n, phi *big.Int) (*big.Int, error) {
	if !validModulus(n) || phi == nil || phi.Sign() <= 0 || phi.Cmp(n) >= 0 {
		return nil, ErrInvalidInput
	}
	sum := new(big.Int).Add(new(big.Int).Sub(n, phi), big.NewInt(1))
	discriminant := new(big.Int).Sub(new(big.Int).Mul(sum, sum), new(big.Int).Lsh(n, 2))
	if discriminant.Sign() < 0 {
		return nil, ErrNoResult
	}
	root := new(big.Int).Sqrt(discriminant)
	if new(big.Int).Mul(root, root).Cmp(discriminant) != 0 {
		return nil, ErrNoResult
	}
	twiceP := new(big.Int).Sub(sum, root)
	if twiceP.Bit(0) != 0 {
		return nil, ErrNoResult
	}
	p := new(big.Int).Rsh(twiceP, 1)
	if p.Cmp(big.NewInt(1)) <= 0 || p.Cmp(n) >= 0 || new(big.Int).Mod(n, p).Sign() != 0 {
		return nil, ErrNoResult
	}
	q := new(big.Int).Quo(n, p)
	if p.Cmp(q) == 0 || !p.ProbablyPrime(32) || !q.ProbablyPrime(32) {
		return nil, ErrNoResult
	}
	return p, nil
}

// FactorFromCRTExponent tries to recover a factor from a full leaked CRT
// exponent dp=d mod (p-1), or equivalently dq. It uses gcd(a^(e*dp-1)-1,n)
// and also checks whether a already shares a factor with n. When that GCD
// equals n, repeated squaring with the odd part of e*dp-1 may expose a
// factor. This does not require dp to be a full private exponent.
// It examines at most attempts consecutive bases starting at 2, stopping
// before n; a zero budget performs no attempts. Exhaustion returns
// ErrNoResult and does not prove that the leak is invalid. Partial-bit
// leaks are not supported. A returned factor need not itself be prime.
func FactorFromCRTExponent(n, e, dp *big.Int, attempts uint64) (*big.Int, error) {
	if !validModulus(n) || !validExponent(e) || !validExponent(dp) {
		return nil, ErrInvalidInput
	}
	one := big.NewInt(1)
	k := new(big.Int).Sub(new(big.Int).Mul(e, dp), one)
	if k.Sign() <= 0 {
		return nil, ErrNoResult
	}
	powersOfTwo := k.TrailingZeroBits()
	oddPart := new(big.Int).Rsh(k, powersOfTwo)
	base := big.NewInt(2)
	for attempt := uint64(0); attempt < attempts && base.Cmp(n) < 0; attempt++ {
		p := new(big.Int).GCD(nil, nil, base, n)
		if p.Cmp(one) > 0 && p.Cmp(n) < 0 {
			return p, nil
		}
		power := new(big.Int).Exp(base, k, n)
		p.GCD(nil, nil, new(big.Int).Sub(power, one), n)
		if p.Cmp(one) > 0 && p.Cmp(n) < 0 {
			return p, nil
		}
		if p.Cmp(n) == 0 && powersOfTwo > 0 {
			power.Exp(base, oddPart, n)
			for step := uint(0); step < powersOfTwo; step++ {
				p.GCD(nil, nil, new(big.Int).Sub(power, one), n)
				if p.Cmp(one) > 0 && p.Cmp(n) < 0 {
					return p, nil
				}
				if p.Cmp(n) == 0 {
					// Both factors already divide power-1, so later
					// squares of this base cannot separate them.
					break
				}
				power.Mul(power, power)
				power.Mod(power, n)
			}
		}
		base.Add(base, one)
	}
	return nil, ErrNoResult
}

func verifiedPlaintext(m, n, e, c *big.Int) bool {
	return validResidue(m, n) && new(big.Int).Exp(m, e, n).Cmp(c) == 0
}
