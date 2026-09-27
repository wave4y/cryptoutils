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

	// This upper bound is strictly larger than the root. Computing the
	// ceiling this way avoids overflow from adding degree to the bit length.
	bits := (uint(x.BitLen())-1)/degree + 1
	lo := big.NewInt(1)
	hi := new(big.Int).Lsh(big.NewInt(1), bits)
	exponent := new(big.Int).SetUint64(uint64(degree))
	one := big.NewInt(1)
	for new(big.Int).Sub(hi, lo).Cmp(one) > 0 {
		mid := new(big.Int).Rsh(new(big.Int).Add(lo, hi), 1)
		power := new(big.Int).Exp(mid, exponent, nil)
		if power.Cmp(x) <= 0 {
			lo = mid
		} else {
			hi = mid
		}
	}
	return lo, new(big.Int).Exp(lo, exponent, nil).Cmp(x) == 0, nil
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
