package rsactf_test

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"math/big"
	"testing"

	cryptoutils "github.com/wave4y/cryptoutils"
	"github.com/wave4y/cryptoutils/rsactf"
)

func integer(n int64) *big.Int { return big.NewInt(n) }

func requireInteger(t *testing.T, got *big.Int, err error, want int64) {
	t.Helper()
	if err != nil || got == nil || got.Cmp(integer(want)) != 0 {
		t.Fatalf("got (%v, %v), want (%d, nil)", got, err, want)
	}
}

func requireError(t *testing.T, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("got error %v, want %v", got, want)
	}
}

func requireFactor(t *testing.T, n, factor *big.Int, err error) {
	t.Helper()
	if err != nil || factor == nil || factor.Cmp(integer(1)) <= 0 || factor.Cmp(n) >= 0 || new(big.Int).Mod(n, factor).Sign() != 0 {
		t.Fatalf("got (%v, %v), want a proper factor of %v", factor, err, n)
	}
}

func TestRawRSA(t *testing.T) {
	cipher, err := rsactf.EncryptRaw(integer(3233), integer(17), integer(65))
	requireInteger(t, cipher, err, 2790)
	plain, err := rsactf.DecryptRaw(integer(3233), integer(2753), cipher)
	requireInteger(t, plain, err, 65)
	for _, m := range []int64{0, 1, 53, 61, 3232} {
		cipher, err = rsactf.EncryptRaw(integer(3233), integer(17), integer(m))
		if err != nil {
			t.Fatal(err)
		}
		plain, err = rsactf.DecryptRaw(integer(3233), integer(2753), cipher)
		requireInteger(t, plain, err, m)
	}
}

func TestRawRSAArbitrarySizeExponents(t *testing.T) {
	// Adding a multiple of phi preserves these exponents for this coprime message.
	multiple := new(big.Int).Mul(integer(3120), new(big.Int).Lsh(integer(1), 100))
	e := new(big.Int).Add(multiple, integer(17))
	d := new(big.Int).Add(multiple, integer(2753))
	cipher, err := rsactf.EncryptRaw(integer(3233), e, integer(65))
	requireInteger(t, cipher, err, 2790)
	plain, err := rsactf.DecryptRaw(integer(3233), d, cipher)
	requireInteger(t, plain, err, 65)
}

func TestRawRSASquareModulus(t *testing.T) {
	// phi(7^2)=42, and 5*17=1 mod 42. The message must be a unit modulo 49.
	cipher, err := rsactf.EncryptRaw(integer(49), integer(5), integer(2))
	requireInteger(t, cipher, err, 32)
	plain, err := rsactf.DecryptRaw(integer(49), integer(17), cipher)
	requireInteger(t, plain, err, 2)
	_, err = rsactf.DecryptCRT(integer(7), integer(7), integer(5), integer(5), cipher)
	requireError(t, err, rsactf.ErrInvalidInput)
}

func TestRawRSARejectsInvalidInputs(t *testing.T) {
	cases := []struct {
		name    string
		n, e, x *big.Int
	}{
		{"nil modulus", nil, integer(17), integer(1)},
		{"unit modulus", integer(1), integer(17), integer(0)},
		{"negative modulus", integer(-5), integer(17), integer(0)},
		{"nil exponent", integer(3233), nil, integer(1)},
		{"zero exponent", integer(3233), integer(0), integer(1)},
		{"negative exponent", integer(3233), integer(-1), integer(1)},
		{"nil representative", integer(3233), integer(17), nil},
		{"negative representative", integer(3233), integer(17), integer(-1)},
		{"out of range", integer(3233), integer(17), integer(3233)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := rsactf.EncryptRaw(tc.n, tc.e, tc.x)
			requireError(t, err, rsactf.ErrInvalidInput)
			_, err = rsactf.DecryptRaw(tc.n, tc.e, tc.x)
			requireError(t, err, rsactf.ErrInvalidInput)
		})
	}
}

func TestDecryptCRT(t *testing.T) {
	for _, m := range []int64{0, 65, 53, 61, 3232} {
		cipher := new(big.Int).Exp(integer(m), integer(17), integer(3233))
		plain, err := rsactf.DecryptCRT(integer(61), integer(53), integer(53), integer(49), cipher)
		requireInteger(t, plain, err, m)
		plain, err = rsactf.DecryptCRT(integer(53), integer(61), integer(49), integer(53), cipher)
		requireInteger(t, plain, err, m)
	}
	cases := [][]*big.Int{
		{nil, integer(53), integer(53), integer(49), integer(2790)},
		{integer(61), nil, integer(53), integer(49), integer(2790)},
		{integer(61), integer(53), nil, integer(49), integer(2790)},
		{integer(61), integer(53), integer(53), nil, integer(2790)},
		{integer(61), integer(53), integer(53), integer(49), nil},
		{integer(61), integer(53), integer(0), integer(49), integer(2790)},
		{integer(61), integer(53), integer(60), integer(49), integer(2790)},
		{integer(61), integer(53), integer(53), integer(52), integer(2790)},
		{integer(61), integer(53), integer(53), integer(49), integer(3233)},
		{integer(9), integer(7), integer(5), integer(5), integer(2)},
	}
	for i, args := range cases {
		if _, err := rsactf.DecryptCRT(args[0], args[1], args[2], args[3], args[4]); !errors.Is(err, rsactf.ErrInvalidInput) {
			t.Errorf("invalid case %d: got %v", i, err)
		}
	}
}

func TestIntegerToBytes(t *testing.T) {
	for _, tc := range []struct {
		x     int64
		width int
		want  []byte
	}{
		{0, 0, []byte{0}}, {0, 3, []byte{0, 0, 0}},
		{65, 0, []byte{65}}, {65, 3, []byte{0, 0, 65}},
		{256, 0, []byte{1, 0}}, {256, 2, []byte{1, 0}},
	} {
		got, err := rsactf.IntegerToBytes(integer(tc.x), tc.width)
		if err != nil || !bytes.Equal(got, tc.want) {
			t.Errorf("IntegerToBytes(%d, %d) = %x, %v; want %x", tc.x, tc.width, got, err, tc.want)
		}
	}
	for _, tc := range []struct {
		x     *big.Int
		width int
	}{{nil, 0}, {integer(-1), 0}, {integer(1), -1}, {integer(256), 1}} {
		_, err := rsactf.IntegerToBytes(tc.x, tc.width)
		requireError(t, err, rsactf.ErrInvalidInput)
	}
}

func TestIntegerRoot(t *testing.T) {
	for _, tc := range []struct {
		x, root int64
		degree  uint
		exact   bool
	}{
		{0, 0, 3, true}, {1, 1, 5, true}, {27, 3, 3, true},
		{26, 2, 3, false}, {28, 3, 3, false}, {81, 9, 2, true},
		{123, 123, 1, true}, {2, 1, ^uint(0), false},
	} {
		got, exact, err := rsactf.IntegerRoot(integer(tc.x), tc.degree)
		requireInteger(t, got, err, tc.root)
		if exact != tc.exact {
			t.Errorf("IntegerRoot(%d, %d): exact=%v, want %v", tc.x, tc.degree, exact, tc.exact)
		}
	}
	root := new(big.Int).Add(new(big.Int).Lsh(integer(1), 512), integer(29))
	power := new(big.Int).Exp(root, integer(7), nil)
	got, exact, err := rsactf.IntegerRoot(power, 7)
	if err != nil || !exact || got.Cmp(root) != 0 {
		t.Fatalf("large root = %v, %v, %v", got, exact, err)
	}
	for _, x := range []*big.Int{nil, integer(-1)} {
		_, _, err := rsactf.IntegerRoot(x, 3)
		requireError(t, err, rsactf.ErrInvalidInput)
	}
	_, _, err = rsactf.IntegerRoot(integer(2), 0)
	requireError(t, err, rsactf.ErrInvalidInput)
}

func TestCRT(t *testing.T) {
	got, err := rsactf.CRT([]*big.Int{integer(3), integer(5), integer(7)}, []*big.Int{integer(2), integer(3), integer(2)})
	requireInteger(t, got, err, 23)
	for _, tc := range []struct{ ns, xs []*big.Int }{
		{nil, nil},
		{[]*big.Int{integer(7)}, []*big.Int{integer(6)}},
		{[]*big.Int{integer(3)}, nil},
		{[]*big.Int{nil, integer(5)}, []*big.Int{integer(0), integer(1)}},
		{[]*big.Int{integer(1), integer(5)}, []*big.Int{integer(0), integer(1)}},
		{[]*big.Int{integer(3), integer(5)}, []*big.Int{nil, integer(1)}},
		{[]*big.Int{integer(3), integer(5)}, []*big.Int{integer(-1), integer(1)}},
		{[]*big.Int{integer(3), integer(5)}, []*big.Int{integer(3), integer(1)}},
		{[]*big.Int{integer(6), integer(9)}, []*big.Int{integer(1), integer(1)}},
	} {
		_, err = rsactf.CRT(tc.ns, tc.xs)
		requireError(t, err, rsactf.ErrInvalidInput)
	}
}

func TestLowExponentBudget(t *testing.T) {
	n, e := integer(11413), integer(3)
	cipher := new(big.Int).Exp(integer(65), e, n)
	plain, err := rsactf.LowExponent(n, e, cipher, 24)
	requireInteger(t, plain, err, 65)
	_, err = rsactf.LowExponent(n, e, cipher, 23)
	requireError(t, err, rsactf.ErrNoResult)
	plain, err = rsactf.LowExponent(n, e, integer(27), 0)
	requireInteger(t, plain, err, 3)
	plain, err = rsactf.LowExponent(n, e, integer(0), 0)
	requireInteger(t, plain, err, 0)
	_, err = rsactf.LowExponent(n, nil, cipher, 24)
	requireError(t, err, rsactf.ErrInvalidInput)
	_, err = rsactf.LowExponent(n, e, n, 24)
	requireError(t, err, rsactf.ErrInvalidInput)
}

func TestBroadcast(t *testing.T) {
	for _, e := range []uint{3, 5} {
		ns := []*big.Int{integer(10807), integer(14803), integer(20413), integer(26219), integer(30967)}[:e]
		cs := make([]*big.Int, len(ns))
		for i, n := range ns {
			cs[i] = new(big.Int).Exp(integer(500), new(big.Int).SetUint64(uint64(e)), n)
		}
		plain, err := rsactf.Broadcast(ns, cs, e)
		requireInteger(t, plain, err, 500)
	}
	// Fewer than e recipients suffice when the actual m^e is below their product.
	plain, err := rsactf.Broadcast([]*big.Int{integer(101), integer(103)}, []*big.Int{integer(8), integer(8)}, 3)
	requireInteger(t, plain, err, 2)
	_, err = rsactf.Broadcast([]*big.Int{integer(101), integer(103)}, []*big.Int{integer(2), integer(2)}, 3)
	requireError(t, err, rsactf.ErrNoResult)
	_, err = rsactf.Broadcast([]*big.Int{integer(101), integer(101)}, []*big.Int{integer(8), integer(8)}, 3)
	requireError(t, err, rsactf.ErrInvalidInput)
	_, err = rsactf.Broadcast(nil, nil, 3)
	requireError(t, err, rsactf.ErrInvalidInput)
}

func TestCommonModulus(t *testing.T) {
	n := integer(1022117)
	for _, exponents := range [][2]int64{{7, 11}, {11, 7}} {
		e1, e2 := integer(exponents[0]), integer(exponents[1])
		c1 := new(big.Int).Exp(integer(500), e1, n)
		c2 := new(big.Int).Exp(integer(500), e2, n)
		plain, err := rsactf.CommonModulus(n, e1, c1, e2, c2)
		requireInteger(t, plain, err, 500)
		_, err = rsactf.CommonModulus(n, e1, c1, e2, integer(1))
		requireError(t, err, rsactf.ErrNoResult)
	}
	plain, err := rsactf.CommonModulus(n, integer(7), integer(0), integer(11), integer(0))
	requireInteger(t, plain, err, 0)
	_, err = rsactf.CommonModulus(n, integer(3), integer(8), integer(9), integer(512))
	requireError(t, err, rsactf.ErrNoResult)
	_, err = rsactf.CommonModulus(n, integer(0), integer(8), integer(11), integer(512))
	requireError(t, err, rsactf.ErrInvalidInput)
	// An exponent with a negative Bezout coefficient needs an invertible ciphertext.
	n = integer(11413)
	c1 := new(big.Int).Exp(integer(101), integer(7), n)
	c2 := new(big.Int).Exp(integer(101), integer(11), n)
	_, err = rsactf.CommonModulus(n, integer(7), c1, integer(11), c2)
	requireError(t, err, rsactf.ErrNoResult)
}

func TestFermat(t *testing.T) {
	factor, err := rsactf.Fermat(integer(1000036000099), 1)
	requireInteger(t, factor, err, 1000003)
	factor, err = rsactf.Fermat(integer(121), 1)
	requireInteger(t, factor, err, 11)
	factor, err = rsactf.Fermat(integer(14), 0)
	requireInteger(t, factor, err, 2)
	factor, err = rsactf.Fermat(integer(21311), 11)
	requireInteger(t, factor, err, 101)
	_, err = rsactf.Fermat(integer(21311), 10)
	requireError(t, err, rsactf.ErrNoResult)
	_, err = rsactf.Fermat(integer(121), 0)
	requireError(t, err, rsactf.ErrNoResult)
	_, err = rsactf.Fermat(integer(101), 100)
	requireError(t, err, rsactf.ErrNoResult)
	_, err = rsactf.Fermat(nil, 1)
	requireError(t, err, rsactf.ErrInvalidInput)
}

func TestFactorFromPhi(t *testing.T) {
	factor, err := rsactf.FactorFromPhi(integer(3233), integer(3120))
	requireInteger(t, factor, err, 53)
	_, err = rsactf.FactorFromPhi(integer(3233), integer(3119))
	requireError(t, err, rsactf.ErrNoResult)
	// The two-distinct-primes identity does not apply to a square modulus.
	_, err = rsactf.FactorFromPhi(integer(49), integer(42))
	requireError(t, err, rsactf.ErrNoResult)
	// An integer discriminant alone does not establish a valid Euler totient.
	for _, pair := range [][2]int64{{9, 4}, {45, 32}, {45, 24}} {
		_, err = rsactf.FactorFromPhi(integer(pair[0]), integer(pair[1]))
		requireError(t, err, rsactf.ErrNoResult)
	}
	_, err = rsactf.FactorFromPhi(integer(3233), nil)
	requireError(t, err, rsactf.ErrInvalidInput)
	_, err = rsactf.FactorFromPhi(integer(3233), integer(3233))
	requireError(t, err, rsactf.ErrInvalidInput)
}

func TestFactorFromCRTExponent(t *testing.T) {
	for _, dp := range []int64{53, 49} {
		factor, err := rsactf.FactorFromCRTExponent(integer(3233), integer(17), integer(dp), 32)
		requireFactor(t, integer(3233), factor, err)
	}
	_, err := rsactf.FactorFromCRTExponent(integer(3233), integer(17), integer(53), 0)
	requireError(t, err, rsactf.ErrNoResult)
	_, err = rsactf.FactorFromCRTExponent(integer(101), integer(17), integer(53), 20)
	requireError(t, err, rsactf.ErrNoResult)
	_, err = rsactf.FactorFromCRTExponent(integer(3233), integer(17), nil, 32)
	requireError(t, err, rsactf.ErrInvalidInput)
}

func TestSharedFactor(t *testing.T) {
	factor, err := rsactf.SharedFactor(integer(10807), integer(11413))
	requireInteger(t, factor, err, 101)
	for _, pair := range [][2]int64{{101, 103}, {10807, 10807}, {101, 10807}} {
		_, err = rsactf.SharedFactor(integer(pair[0]), integer(pair[1]))
		requireError(t, err, rsactf.ErrNoResult)
	}
	_, err = rsactf.SharedFactor(nil, integer(11413))
	requireError(t, err, rsactf.ErrInvalidInput)
}

func TestInputsAreNotMutatedOrAliased(t *testing.T) {
	n, e, d, p, q, dp, dq := integer(3233), integer(17), integer(2753), integer(61), integer(53), integer(53), integer(49)
	m, c, phi := integer(65), integer(2790), integer(3120)
	inputs := []*big.Int{n, e, d, p, q, dp, dq, m, c, phi}
	before := make([]string, len(inputs))
	for i, value := range inputs {
		before[i] = value.String()
	}
	calls := []func() (*big.Int, error){
		func() (*big.Int, error) { return rsactf.EncryptRaw(n, e, m) },
		func() (*big.Int, error) { return rsactf.DecryptRaw(n, d, c) },
		func() (*big.Int, error) { return rsactf.DecryptCRT(p, q, dp, dq, c) },
		func() (*big.Int, error) { return rsactf.CRT([]*big.Int{p, q}, []*big.Int{integer(4), integer(12)}) },
		func() (*big.Int, error) { return rsactf.FactorFromPhi(n, phi) },
		func() (*big.Int, error) { return rsactf.FactorFromCRTExponent(n, e, dp, 32) },
		func() (*big.Int, error) { return rsactf.Fermat(n, 10) },
	}
	for _, call := range calls {
		out, err := call()
		if err != nil {
			t.Fatal(err)
		}
		out.SetInt64(0)
		for i, value := range inputs {
			if value.String() != before[i] {
				t.Fatalf("input %d changed from %s to %s", i, before[i], value)
			}
		}
	}
	// The degree-one shortcut must return a fresh value too.
	root, _, err := rsactf.IntegerRoot(m, 1)
	if err != nil {
		t.Fatal(err)
	}
	root.SetInt64(0)
	requireInteger(t, m, nil, 65)
}

func TestAttackInputsAreNotMutatedOrAliased(t *testing.T) {
	ns := []*big.Int{integer(10807), integer(14803), integer(20413)}
	cs := make([]*big.Int, len(ns))
	e := integer(3)
	for i, n := range ns {
		cs[i] = new(big.Int).Exp(integer(500), e, n)
	}
	n, e1, e2 := integer(1022117), integer(7), integer(11)
	c1, c2 := new(big.Int).Exp(integer(500), e1, n), new(big.Int).Exp(integer(500), e2, n)
	lowN := integer(11413)
	lowC := new(big.Int).Exp(integer(65), e, lowN)
	inputs := append(append([]*big.Int{}, ns...), cs...)
	inputs = append(inputs, e, n, e1, e2, c1, c2, lowN, lowC)
	before := make([]string, len(inputs))
	for i, value := range inputs {
		before[i] = value.String()
	}
	calls := []func() (*big.Int, error){
		func() (*big.Int, error) { return rsactf.Broadcast(ns, cs, 3) },
		func() (*big.Int, error) { return rsactf.LowExponent(lowN, e, lowC, 24) },
		func() (*big.Int, error) { return rsactf.CommonModulus(n, e1, c1, e2, c2) },
		func() (*big.Int, error) { return rsactf.SharedFactor(ns[0], lowN) },
	}
	for _, call := range calls {
		out, err := call()
		if err != nil {
			t.Fatal(err)
		}
		out.SetInt64(0)
		for i, value := range inputs {
			if value.String() != before[i] {
				t.Fatalf("input %d changed from %s to %s", i, before[i], value)
			}
		}
	}
}

func TestRecoveredKeyWithProductionOAEPAndPEM(t *testing.T) {
	key, err := cryptoutils.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	phi := new(big.Int).Mul(new(big.Int).Sub(key.Primes[0], integer(1)), new(big.Int).Sub(key.Primes[1], integer(1)))
	p, err := rsactf.FactorFromPhi(key.N, phi)
	requireFactor(t, key.N, p, err)
	q := new(big.Int).Quo(key.N, p)
	d := new(big.Int).ModInverse(integer(int64(key.E)), phi)
	recovered := &rsa.PrivateKey{PublicKey: key.PublicKey, D: d, Primes: []*big.Int{p, q}}
	message, label := []byte("flag{recovered_rsa_key}"), []byte("rsactf integration")
	ciphertext, err := cryptoutils.EncryptRSAOAEP(message, &key.PublicKey, label)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := cryptoutils.DecryptRSAOAEP(ciphertext, recovered, label)
	if err != nil || !bytes.Equal(plaintext, message) {
		t.Fatalf("recovered-key OAEP decrypt = %q, %v", plaintext, err)
	}
	encoded, err := cryptoutils.MarshalPrivateKeyPEM(recovered)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := cryptoutils.ParsePrivateKeyPEM(encoded)
	if err != nil {
		t.Fatal(err)
	}
	parsedRSA, ok := parsed.(*rsa.PrivateKey)
	if !ok || parsedRSA.N.Cmp(key.N) != 0 || parsedRSA.D.Cmp(d) != 0 {
		t.Fatalf("PEM round trip returned incorrect key: %T", parsed)
	}
	plaintext, err = cryptoutils.DecryptRSAOAEP(ciphertext, parsedRSA, label)
	if err != nil || !bytes.Equal(plaintext, message) {
		t.Fatalf("PEM-imported OAEP decrypt = %q, %v", plaintext, err)
	}
	// Adding textbook operations must not relax the existing padded-RSA API.
	t.Run("standard API restrictions remain", func(t *testing.T) {
		small := &rsa.PublicKey{N: integer(3233), E: 17}
		_, err := cryptoutils.EncryptRSAOAEP([]byte("A"), small, nil)
		requireError(t, err, cryptoutils.ErrInvalidAsymmetricKey)
		if _, err = cryptoutils.GenerateRSAKey(512); err == nil {
			t.Fatal("production key generator accepted 512 bits")
		}
		incomplete := &rsa.PrivateKey{PublicKey: key.PublicKey, D: key.D}
		_, err = cryptoutils.MarshalPrivateKeyPEM(incomplete)
		requireError(t, err, cryptoutils.ErrInvalidAsymmetricKey)
		raw, err := rsactf.EncryptRaw(key.N, integer(int64(key.E)), integer(65))
		if err != nil {
			t.Fatal(err)
		}
		rawBytes, err := rsactf.IntegerToBytes(raw, key.Size())
		if err != nil {
			t.Fatal(err)
		}
		if _, err = cryptoutils.DecryptRSAOAEP(rawBytes, key, nil); err == nil {
			t.Fatal("OAEP accepted unpadded RSA ciphertext")
		}
	})
}
