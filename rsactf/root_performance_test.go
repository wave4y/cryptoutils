package rsactf_test

import (
	"fmt"
	"math/big"
	"math/rand"
	"testing"

	"github.com/wave4y/cryptoutils/rsactf"
)

// smallRootOracle enumerates candidate roots using checked uint64 arithmetic.
// It deliberately shares neither big.Int arithmetic nor Newton iteration with
// IntegerRoot, so small exhaustive cases provide an independent comparison.
func smallRootOracle(x uint64, degree uint) (uint64, bool) {
	if degree == 1 || x < 2 {
		return x, true
	}
	var root, lastPower uint64
	for candidate := uint64(1); ; candidate++ {
		power := uint64(1)
		for exponent := uint(0); exponent < degree; exponent++ {
			if power > x/candidate {
				return root, lastPower == x
			}
			power *= candidate
		}
		root, lastPower = candidate, power
	}
}

func checkSmallRoot(t *testing.T, x uint64, degree uint) {
	t.Helper()
	want, wantExact := smallRootOracle(x, degree)
	got, exact, err := rsactf.IntegerRoot(new(big.Int).SetUint64(x), degree)
	if err != nil || got == nil || !got.IsUint64() || got.Uint64() != want || exact != wantExact {
		t.Fatalf("IntegerRoot(%d, %d) = (%v, %v, %v), want (%d, %v, nil)", x, degree, got, exact, err, want, wantExact)
	}
}

func TestIntegerRootExhaustiveSmallOracle(t *testing.T) {
	for x := uint64(0); x <= 2048; x++ {
		for degree := uint(1); degree <= 16; degree++ {
			checkSmallRoot(t, x, degree)
		}
	}
}

func TestIntegerRootDeterministicRandomOracle(t *testing.T) {
	rng := rand.New(rand.NewSource(20260927))
	for i := 0; i < 1000; i++ {
		checkSmallRoot(t, uint64(rng.Int63n(1<<20)), uint(1+rng.Intn(64)))
	}
}

func TestIntegerRootPowerBoundaries(t *testing.T) {
	for _, bits := range []uint{2, 9, 64, 257} {
		for _, delta := range []int64{-1, 0, 1} {
			root := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), bits), big.NewInt(delta))
			for _, degree := range []uint{2, 3, 4, 5, 17, 64, 127} {
				checkRootPowerBoundary(t, root, degree)
			}
		}
	}
}

func checkRootPowerBoundary(t *testing.T, root *big.Int, degree uint) {
	t.Helper()
	power := new(big.Int).Exp(root, new(big.Int).SetUint64(uint64(degree)), nil)
	for _, delta := range []int64{-1, 0, 1} {
		x := new(big.Int).Add(power, big.NewInt(delta))
		original := new(big.Int).Set(x)
		want := new(big.Int).Set(root)
		if delta < 0 {
			want.Sub(want, big.NewInt(1))
		}
		got, exact, err := rsactf.IntegerRoot(x, degree)
		if err != nil || got == nil || got.Cmp(want) != 0 || exact != (delta == 0) {
			t.Fatalf("root bits=%d, degree=%d, delta=%d: got (%v, %v, %v), want (%v, %v, nil)", root.BitLen(), degree, delta, got, exact, err, want, delta == 0)
		}
		if x.Cmp(original) != 0 {
			t.Fatal("IntegerRoot modified its input")
		}
		got.SetInt64(0)
		if x.Cmp(original) != 0 {
			t.Fatal("IntegerRoot returned an alias of its input")
		}
	}
}

func TestIntegerRootLargeAndHighDegree(t *testing.T) {
	root := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 8192), big.NewInt(997))
	checkRootPowerBoundary(t, root, 3)
	checkRootPowerBoundary(t, big.NewInt(3), 4096)
	for _, degree := range []uint{1023, 1024, 1025, ^uint(0)} {
		x := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 1024), big.NewInt(1))
		want := int64(1)
		if degree == 1023 {
			want = 2
		}
		got, exact, err := rsactf.IntegerRoot(x, degree)
		if err != nil || got == nil || got.Cmp(big.NewInt(want)) != 0 || exact {
			t.Fatalf("high degree %d: got (%v, %v, %v), want (%d, false, nil)", degree, got, exact, err, want)
		}
	}
}

func TestIntegerRootRandomLargeBounds(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for _, size := range []int{8, 31, 128, 512, 2048} {
		data := make([]byte, size)
		if _, err := rng.Read(data); err != nil {
			t.Fatal(err)
		}
		data[0] |= 0x80
		x := new(big.Int).SetBytes(data)
		for _, degree := range []uint{3, 5, 7, 17, 31, 64} {
			root, exact, err := rsactf.IntegerRoot(x, degree)
			if err != nil || root == nil {
				t.Fatalf("%d bytes, degree=%d: %v", size, degree, err)
			}
			exponent := new(big.Int).SetUint64(uint64(degree))
			lower := new(big.Int).Exp(root, exponent, nil)
			upper := new(big.Int).Exp(new(big.Int).Add(root, big.NewInt(1)), exponent, nil)
			if lower.Cmp(x) > 0 || upper.Cmp(x) <= 0 || exact != (lower.Cmp(x) == 0) {
				t.Fatalf("%d bytes, degree=%d: returned root violates floor-root bounds", size, degree)
			}
		}
	}
}

func BenchmarkIntegerRoot4096Bit(b *testing.B) {
	data := make([]byte, 512)
	rng := rand.New(rand.NewSource(7))
	if _, err := rng.Read(data); err != nil {
		b.Fatal(err)
	}
	data[0] |= 0x80
	x := new(big.Int).SetBytes(data)
	for _, degree := range []uint{3, 5, 17, 64} {
		b.Run(fmt.Sprintf("degree_%d", degree), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, _, err := rsactf.IntegerRoot(x, degree); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
