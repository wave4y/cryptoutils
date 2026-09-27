package rsactf

import "math/big"

// IntegerRoot returns floor(x^(1/degree)) and whether the root is exact.
// It accepts nonnegative x and degree >= 1, and never modifies x. Large
// degrees are handled without constructing an exponentially large power.
func IntegerRoot(x *big.Int, degree uint) (*big.Int, bool, error) {
	if x == nil || x.Sign() < 0 || degree == 0 {
		return nil, false, ErrInvalidInput
	}
	if degree == 1 || x.Cmp(big.NewInt(1)) <= 0 {
		return new(big.Int).Set(x), true, nil
	}
	if degree >= uint(x.BitLen()) {
		return big.NewInt(1), false, nil
	}
	if degree == 2 {
		root := new(big.Int).Sqrt(x)
		return root, new(big.Int).Mul(root, root).Cmp(x) == 0, nil
	}

	// Start above the real root. Computing the ceiling this way avoids
	// overflow from adding degree to the bit length.
	bits := (uint(x.BitLen())-1)/degree + 1
	root := new(big.Int).Lsh(big.NewInt(1), bits)
	exponent := new(big.Int).SetUint64(uint64(degree))
	previousExponent := new(big.Int).Sub(exponent, big.NewInt(1))
	power, quotient, next := new(big.Int), new(big.Int), new(big.Int)
	for {
		// Integer Newton step: ((degree-1)*root + x/root^(degree-1))/degree.
		// Starting above the real root, this strictly decreases until the
		// floor root, never undershooting it. At the floor root it may
		// increase, so stop at the first nondecreasing step to avoid cycles.
		power.Exp(root, previousExponent, nil)
		quotient.Quo(x, power)
		next.Mul(root, previousExponent)
		next.Add(next, quotient)
		next.Quo(next, exponent)
		if next.Cmp(root) >= 0 {
			return root, power.Mul(power, root).Cmp(x) == 0, nil
		}
		root, next = next, root
	}
}

// CRT combines at least two congruences with pairwise coprime moduli > 1.
// Every residue must be canonical: 0 <= residues[i] < moduli[i]. It returns
// the unique nonnegative result below the product of the moduli. Invalid
// lengths, residues, or noncoprime moduli produce ErrInvalidInput.
func CRT(moduli, residues []*big.Int) (*big.Int, error) {
	if len(moduli) < 2 || len(moduli) != len(residues) {
		return nil, ErrInvalidInput
	}
	product := big.NewInt(1)
	for i, modulus := range moduli {
		if !validModulus(modulus) || !validResidue(residues[i], modulus) {
			return nil, ErrInvalidInput
		}
		product.Mul(product, modulus)
	}

	result := new(big.Int)
	for i, modulus := range moduli {
		part := new(big.Int).Quo(product, modulus)
		inverse := new(big.Int).ModInverse(part, modulus)
		if inverse == nil {
			return nil, ErrInvalidInput
		}
		term := new(big.Int).Mul(part, inverse)
		term.Mul(term, residues[i])
		result.Add(result, term)
	}
	return result.Mod(result, product), nil
}
