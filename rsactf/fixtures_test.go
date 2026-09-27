package rsactf_test

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/wave4y/cryptoutils/rsactf"
)

// Public challenge data is pinned and attributed in testdata/rsactftool.json.
// Every recovered integer is also checked by re-encrypting all observations.
func TestRsaCtfToolRealFixtures(t *testing.T) {
	var dataset struct {
		Cases []struct {
			ID          string                     `json:"id"`
			Method      string                     `json:"method"`
			Params      map[string]json.RawMessage `json:"params"`
			ExpectedHex string                     `json:"expected_hex"`
		} `json:"cases"`
	}
	data, err := os.ReadFile("testdata/rsactftool.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &dataset); err != nil {
		t.Fatal(err)
	}
	if len(dataset.Cases) != 4 {
		t.Fatal("incomplete real-fixture set")
	}
	parse := func(t *testing.T, raw json.RawMessage) *big.Int {
		t.Helper()
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatal(err)
		}
		n, ok := new(big.Int).SetString(value, 10)
		if !ok {
			t.Fatal("invalid fixture integer")
		}
		return n
	}
	for _, tc := range dataset.Cases {
		t.Run(tc.ID, func(t *testing.T) {
			e := parse(t, tc.Params["e"])
			var err error
			var n, c, m *big.Int
			var ns, cs []*big.Int
			if tc.Method == "broadcast" {
				var nRaw, cRaw []json.RawMessage
				if err := json.Unmarshal(tc.Params["n"], &nRaw); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(tc.Params["c"], &cRaw); err != nil {
					t.Fatal(err)
				}
				for _, v := range nRaw {
					ns = append(ns, parse(t, v))
				}
				for _, v := range cRaw {
					cs = append(cs, parse(t, v))
				}
				m, err = rsactf.Broadcast(ns, cs, uint(e.Uint64()))
			} else {
				n, c = parse(t, tc.Params["n"]), parse(t, tc.Params["c"])
				if tc.Method == "fermat" {
					var p *big.Int
					p, err = rsactf.Fermat(n, 10000)
					if err != nil {
						t.Fatal(err)
					}
					q := new(big.Int).Quo(n, p)
					if new(big.Int).Mul(p, q).Cmp(n) != 0 {
						t.Fatal("wrong factorization")
					}
					phi := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))
					d := new(big.Int).ModInverse(e, phi)
					if d == nil {
						t.Fatal("no private exponent")
					}
					m, err = rsactf.DecryptRaw(n, d, c)
				} else {
					m, err = rsactf.LowExponent(n, e, c, 10000)
				}
				ns, cs = []*big.Int{n}, []*big.Int{c}
			}
			if err != nil {
				t.Fatal(err)
			}
			b, err := rsactf.IntegerToBytes(m, 0)
			if err != nil || hex.EncodeToString(b) != tc.ExpectedHex {
				t.Fatalf("unexpected plaintext: %x %v", b, err)
			}
			for i, n := range ns {
				if new(big.Int).Exp(m, e, n).Cmp(cs[i]) != 0 {
					t.Fatal("ciphertext mismatch")
				}
			}
			if raw := tc.Params["e1"]; len(raw) > 0 {
				if new(big.Int).Exp(m, parse(t, raw), n).Cmp(parse(t, tc.Params["c1"])) != 0 {
					t.Fatal("second ciphertext mismatch")
				}
			}
		})
	}
}
