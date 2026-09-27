package zuc

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func hx(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// Published ETSI/SAGE and ZUC-256 specification vectors, also reproduced at:
// https://github.com/guanzhi/GmSSL/blob/master/tests/zuctest.c
func TestKnownKeystreams(t *testing.T) {
	for _, tc := range []struct{ k, v, w string }{
		{"00000000000000000000000000000000", "00000000000000000000000000000000", "27bede74018082da"},
		{"ffffffffffffffffffffffffffffffff", "ffffffffffffffffffffffffffffffff", "0657cfa07096398b"},
		{"3d4c4be96a82fdaeb58f641db17b455b", "84319aa8de6915ca1f6bda6bfbd8c766", "14f1c2723279c419"},
		{"0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000", "58d03ad62e032ce2dafc683a39bdcb0352a2bc67f1b7de74163ce3a101ef55589639d75b95fa681b7f090df756391ccc903b7612744d544c17bc3fad8b163b0821787c0b97775bb84943c6bbe8ad8afd"},
		{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "ffffffffffffffffffffffffffffffffffffffffffffff", "3356cbaed1a1c18b6baa4ffe343f777c9e15128f251ab65b949f7b26ef7157f296dd2fa9df95e3ee7a5be02ec32ba585505af316c2f9ded27cdbd935e441ce1115fd0a80bb7aef6768989416b8fac8c2"},
	} {
		want := hx(tc.w)
		got, err := Crypt(make([]byte, len(want)), hx(tc.k), hx(tc.v))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("keystream: %x (%v), want %x", got, err, want)
		}
	}
}
func TestMACVectors(t *testing.T) {
	got, err := MACBits([]byte{0}, 1, make([]byte, 16), make([]byte, 16), 4)
	if err != nil || !bytes.Equal(got, hx("c8a9595e")) {
		t.Fatalf("128 MAC %x %v", got, err)
	}
	vectors := [4][3]string{
		{"9b972a74", "673e54990034d38c", "d85e54bbcb9600967084c952a1654b26"},
		{"8754f5cf", "130dc225e72240cc", "df1e8307b31cc62beca1ac6f8190c22f"},
		{"1f3079b4", "8c71394d39957725", "a35bb274b567c48b28319f111af34fbd"},
		{"5c7c8b88", "ea1dee544bb6223b", "3a83b554be408ca5494124ed9d473205"},
	}
	for i, vs := range vectors {
		k, v := make([]byte, 32), make([]byte, 23)
		if i >= 2 {
			k = bytes.Repeat([]byte{255}, 32)
			v = bytes.Repeat([]byte{255}, 23)
		}
		msg := make([]byte, 50)
		if i%2 == 1 {
			msg = bytes.Repeat([]byte{0x11}, 500)
		}
		for _, w := range vs {
			want := hx(w)
			tag, err := MAC(msg, k, v, len(want))
			if err != nil || !bytes.Equal(tag, want) {
				t.Fatalf("256 MAC %d: %x %v want %x", i, tag, err, want)
			}
			ok, err := VerifyMAC(msg, k, v, tag)
			if err != nil || !ok {
				t.Fatal("verify", err)
			}
			tag[0] ^= 1
			if ok, _ := VerifyMAC(msg, k, v, tag); ok {
				t.Fatal("tampered tag")
			}
		}
	}
}
func TestStreamFragments(t *testing.T) {
	for _, size := range []int{16, 32} {
		k := make([]byte, size)
		v := make([]byte, 16)
		if size == 32 {
			v = make([]byte, 23)
		}
		msg := bytes.Repeat([]byte("a message"), 30)
		want, _ := Crypt(msg, k, v)
		for _, step := range []int{1, 3, 4, 5, 31} {
			c, _ := NewCipher(k, v)
			got := append([]byte(nil), msg...)
			for i := 0; i < len(got); i += step {
				end := i + step
				if end > len(got) {
					end = len(got)
				}
				c.XORKeyStream(got[i:end], got[i:end])
			}
			if !bytes.Equal(got, want) {
				t.Fatal("fragmented stream")
			}
		}
		plain, _ := Crypt(want, k, v)
		if !bytes.Equal(plain, msg) {
			t.Fatal("decrypt")
		}
	}
}
func TestValidation(t *testing.T) {
	for _, kv := range [][2]int{{0, 0}, {15, 16}, {16, 15}, {32, 16}, {32, 24}} {
		if _, err := NewCipher(make([]byte, kv[0]), make([]byte, kv[1])); err == nil {
			t.Fatal("bad lengths")
		}
	}
	for _, n := range []int{-1, 9} {
		if _, err := MACBits([]byte{0}, n, make([]byte, 16), make([]byte, 16), 4); err == nil {
			t.Fatal("bad bit count")
		}
	}
	for _, tag := range []int{0, 1, 3, 5, 8} {
		if _, err := MAC(nil, make([]byte, 16), make([]byte, 16), tag); err == nil {
			t.Fatal("bad tag")
		}
	}
	for _, f := range []func(){func() { c, _ := NewCipher(make([]byte, 16), make([]byte, 16)); c.XORKeyStream(nil, []byte{1}) }, func() {
		c, _ := NewCipher(make([]byte, 16), make([]byte, 16))
		b := make([]byte, 10)
		c.XORKeyStream(b[1:], b[:9])
	}} {
		func() {
			defer func() {
				if recover() == nil {
					t.Error("expected panic")
				}
			}()
			f()
		}()
	}
}
