package cryptoutils_test

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	c "github.com/wave4y/cryptoutils"
)

func TestRSACTFRawOperations(t *testing.T) {
	n, e, d := big.NewInt(3233), big.NewInt(17), big.NewInt(2753)
	m := big.NewInt(65)
	ciphertext, err := c.EncryptRSARaw(n, e, m)
	if err != nil || ciphertext.Cmp(big.NewInt(2790)) != 0 {
		t.Fatalf("raw encrypt: %v, %v", ciphertext, err)
	}
	plain, err := c.DecryptRSARaw(n, d, ciphertext)
	if err != nil || plain.Cmp(m) != 0 {
		t.Fatalf("raw decrypt: %v, %v", plain, err)
	}
	plain, err = c.DecryptRSACRT(big.NewInt(61), big.NewInt(53), big.NewInt(53), big.NewInt(49), ciphertext)
	if err != nil || plain.Cmp(m) != 0 {
		t.Fatalf("CRT decrypt: %v, %v", plain, err)
	}
	// Equivalent exponents outside int64 still work in the CTF interface.
	largeE := new(big.Int).Lsh(big.NewInt(3120), 70)
	largeE.Add(largeE, e)
	got, err := c.EncryptRSARaw(n, largeE, m)
	if err != nil || got.Cmp(ciphertext) != 0 {
		t.Fatalf("large exponent: %v, %v", got, err)
	}
	if n.Int64() != 3233 || e.Int64() != 17 || d.Int64() != 2753 || m.Int64() != 65 || ciphertext.Int64() != 2790 {
		t.Fatal("raw operations changed caller-owned parameters")
	}
}

func TestRSACTFAttackHelpers(t *testing.T) {
	root, exact, err := c.RSAIntegerRoot(big.NewInt(1000), 3)
	if err != nil || !exact || root.Cmp(big.NewInt(10)) != 0 {
		t.Fatalf("integer root: %v, %v, %v", root, exact, err)
	}
	root, exact, err = c.RSAIntegerRoot(big.NewInt(1001), 3)
	if err != nil || exact || root.Cmp(big.NewInt(10)) != 0 {
		t.Fatalf("non-exact integer root: %v, %v, %v", root, exact, err)
	}

	for _, tc := range []struct {
		name string
		call func() (*big.Int, error)
		want int64
	}{
		{"CRT", func() (*big.Int, error) {
			return c.RSACRT([]*big.Int{big.NewInt(3), big.NewInt(5), big.NewInt(7)}, []*big.Int{big.NewInt(2), big.NewInt(3), big.NewInt(2)})
		}, 23},
		{"low exponent", func() (*big.Int, error) {
			return c.RSALowExponent(big.NewInt(55), big.NewInt(3), big.NewInt(13), 6)
		}, 7},
		{"broadcast", func() (*big.Int, error) {
			ns := []*big.Int{big.NewInt(11413), big.NewInt(13589), big.NewInt(14279)}
			cs := make([]*big.Int, len(ns))
			for i, n := range ns {
				cs[i] = new(big.Int).Exp(big.NewInt(123), big.NewInt(3), n)
			}
			return c.RSABroadcast(ns, cs, 3)
		}, 123},
		{"common modulus", func() (*big.Int, error) {
			n := big.NewInt(3233)
			c2 := new(big.Int).Exp(big.NewInt(65), big.NewInt(7), n)
			return c.RSACommonModulus(n, big.NewInt(17), big.NewInt(2790), big.NewInt(7), c2)
		}, 65},
		{"shared factor", func() (*big.Int, error) {
			return c.RSASharedFactor(big.NewInt(3233), big.NewInt(4087))
		}, 61},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.call()
			if err != nil || got.Cmp(big.NewInt(tc.want)) != 0 {
				t.Fatalf("got %v, %v; want %d", got, err, tc.want)
			}
		})
	}
	for _, tc := range []struct {
		name string
		call func() (*big.Int, error)
	}{
		{"Fermat", func() (*big.Int, error) { return c.RSAFermat(big.NewInt(3233), 8) }},
		{"phi", func() (*big.Int, error) { return c.RSAFactorFromPhi(big.NewInt(3233), big.NewInt(3120)) }},
		{"CRT exponent", func() (*big.Int, error) {
			return c.RSAFactorFromCRTExponent(big.NewInt(3233), big.NewInt(17), big.NewInt(53), 16)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			factor, err := tc.call()
			if err != nil || (factor.Cmp(big.NewInt(53)) != 0 && factor.Cmp(big.NewInt(61)) != 0) {
				t.Fatalf("factor: %v, %v", factor, err)
			}
		})
	}
}

func TestRSACTFIntegerBytes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		x     *big.Int
		width int
		want  []byte
	}{
		{"zero", big.NewInt(0), 0, []byte{0}},
		{"zero padded", big.NewInt(0), 3, []byte{0, 0, 0}},
		{"minimal", big.NewInt(258), 0, []byte{1, 2}},
		{"fixed", big.NewInt(258), 4, []byte{0, 0, 1, 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := c.RSAIntegerToBytes(tc.x, tc.width)
			if err != nil || !bytes.Equal(got, tc.want) {
				t.Fatalf("bytes: %x, %v; want %x", got, err, tc.want)
			}
		})
	}
	for _, tc := range []struct {
		x     *big.Int
		width int
	}{{nil, 0}, {big.NewInt(-1), 0}, {big.NewInt(1), -1}, {big.NewInt(256), 1}} {
		if got, err := c.RSAIntegerToBytes(tc.x, tc.width); got != nil || !errors.Is(err, c.ErrInvalidRSACTFInput) {
			t.Fatalf("invalid integer/width returned %x, %v", got, err)
		}
	}
}

func TestRSACTFErrorSentinels(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func() (*big.Int, error)
	}{
		{"encrypt", func() (*big.Int, error) { return c.EncryptRSARaw(nil, big.NewInt(3), big.NewInt(1)) }},
		{"decrypt", func() (*big.Int, error) { return c.DecryptRSARaw(big.NewInt(55), nil, big.NewInt(1)) }},
		{"ciphertext range", func() (*big.Int, error) {
			return c.DecryptRSARaw(big.NewInt(55), big.NewInt(27), big.NewInt(55))
		}},
		{"CRT decrypt", func() (*big.Int, error) { return c.DecryptRSACRT(nil, nil, nil, nil, nil) }},
		{"CRT", func() (*big.Int, error) { return c.RSACRT(nil, nil) }},
		{"low exponent", func() (*big.Int, error) { return c.RSALowExponent(nil, nil, nil, 0) }},
		{"broadcast", func() (*big.Int, error) { return c.RSABroadcast(nil, nil, 3) }},
		{"common modulus", func() (*big.Int, error) { return c.RSACommonModulus(nil, nil, nil, nil, nil) }},
		{"shared factor", func() (*big.Int, error) { return c.RSASharedFactor(nil, nil) }},
		{"Fermat", func() (*big.Int, error) { return c.RSAFermat(nil, 1) }},
		{"phi", func() (*big.Int, error) { return c.RSAFactorFromPhi(nil, nil) }},
		{"CRT exponent", func() (*big.Int, error) { return c.RSAFactorFromCRTExponent(nil, nil, nil, 1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.call()
			if got != nil || !errors.Is(err, c.ErrInvalidRSACTFInput) {
				t.Fatalf("invalid input returned %v, %v", got, err)
			}
		})
	}
	if got, _, err := c.RSAIntegerRoot(nil, 3); got != nil || !errors.Is(err, c.ErrInvalidRSACTFInput) {
		t.Fatalf("invalid integer root returned %v, %v", got, err)
	}
	if got, err := c.RSALowExponent(big.NewInt(55), big.NewInt(3), big.NewInt(13), 0); got != nil || !errors.Is(err, c.ErrRSACTFNoResult) {
		t.Fatalf("exhausted search returned %v, %v", got, err)
	}
	if got, err := c.RSASharedFactor(big.NewInt(35), big.NewInt(143)); got != nil || !errors.Is(err, c.ErrRSACTFNoResult) {
		t.Fatalf("coprime moduli returned %v, %v", got, err)
	}
}

func TestRSARawChain(t *testing.T) {
	n, e, d := big.NewInt(3233), big.NewInt(17), big.NewInt(2753)
	message := []byte{0, 65}
	p := c.Init(message)
	if got := p.RSARawEncrypt(n, e); got != p || got.Err() != nil || !bytes.Equal(got.Bytes(), []byte{10, 230}) {
		t.Fatalf("encrypt chain: %x, %v", got.Bytes(), got.Err())
	}
	if got := p.RSARawDecrypt(n, d, 2); got != p || got.Err() != nil || !bytes.Equal(got.Bytes(), message) {
		t.Fatalf("decrypt chain: %x, %v", got.Bytes(), got.Err())
	}
	if p.Reset().Err() != nil || !bytes.Equal(p.Bytes(), message) {
		t.Fatal("Reset did not restore original plaintext")
	}
	p.RSARawEncrypt(n, e).RSARawDecrypt(n, d, 0)
	if p.Err() != nil || !bytes.Equal(p.Bytes(), []byte{65}) {
		t.Fatalf("minimal decrypt: %x, %v", p.Bytes(), p.Err())
	}
	for _, input := range [][]byte{nil, {0}, {0, 0}} {
		p := c.Init(input).RSARawEncrypt(n, e)
		if p.Err() != nil || !bytes.Equal(p.Bytes(), []byte{0, 0}) {
			t.Fatalf("zero encrypt: %x, %v", p.Bytes(), p.Err())
		}
		p.RSARawDecrypt(n, d, 0)
		if p.Err() != nil || !bytes.Equal(p.Bytes(), []byte{0}) {
			t.Fatalf("zero decrypt: %x, %v", p.Bytes(), p.Err())
		}
	}
}

func TestRSARawChainFailures(t *testing.T) {
	n, e, d := big.NewInt(3233), big.NewInt(17), big.NewInt(2753)
	for _, tc := range []struct {
		name  string
		input []byte
		fail  func(*c.CryptoData) *c.CryptoData
	}{
		{"nil modulus", []byte{65}, func(p *c.CryptoData) *c.CryptoData { return p.RSARawEncrypt(nil, e) }},
		{"nil exponent", []byte{65}, func(p *c.CryptoData) *c.CryptoData { return p.RSARawEncrypt(n, nil) }},
		{"plaintext range", n.Bytes(), func(p *c.CryptoData) *c.CryptoData { return p.RSARawEncrypt(n, e) }},
		{"ciphertext range", n.Bytes(), func(p *c.CryptoData) *c.CryptoData { return p.RSARawDecrypt(n, d, 0) }},
		{"nil private exponent", []byte{1}, func(p *c.CryptoData) *c.CryptoData { return p.RSARawDecrypt(n, nil, 0) }},
		{"negative width", []byte{10, 230}, func(p *c.CryptoData) *c.CryptoData { return p.RSARawDecrypt(n, d, -1) }},
		{"narrow width", new(big.Int).Exp(big.NewInt(256), e, n).Bytes(), func(p *c.CryptoData) *c.CryptoData { return p.RSARawDecrypt(n, d, 1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.fail(c.Init(tc.input))
			first := p.Err()
			if !errors.Is(first, c.ErrInvalidRSACTFInput) {
				t.Fatalf("invalid raw RSA input: %v", first)
			}
			p.RSARawEncrypt(n, e).RSARawDecrypt(n, d, 0).Hex()
			if p.Err() != first || p.Bytes() != nil {
				t.Fatal("failed chain continued or lost error")
			}
			if result, err := p.Result(); result != nil || err != first {
				t.Fatalf("Result after failure: %x, %v", result, err)
			}
			if p.Reset().Err() != nil || !bytes.Equal(p.Bytes(), tc.input) {
				t.Fatal("Reset did not restore original input")
			}
		})
	}
	// An earlier operation's error takes precedence even over nil RSA inputs.
	p := c.Init("!").HexDecode()
	first := p.Err()
	p.RSARawEncrypt(nil, nil).RSARawDecrypt(nil, nil, -1)
	if first == nil || p.Err() != first || p.Bytes() != nil {
		t.Fatal("raw RSA replaced a prior chain error")
	}
}
