package mldsa65

import (
	"bytes"
	"fmt"
	"testing"
	"www.gitlablow.com/wave4y/cryptoutils/pqc/internal/kat"
)

func TestNISTACVPInternal(t *testing.T) {
	for _, tc := range kat.Load(t, "ML-DSA") {
		if tc.Parameter != "ML-DSA-65" || tc.Operation == "keyGen" {
			continue
		}
		t.Run(fmt.Sprintf("%s/%d", tc.Operation, tc.Input.TcID), func(t *testing.T) {
			switch tc.Operation {
			case "sigGen":
				var sk PrivateKey
				if err := sk.UnmarshalBinary(tc.Input.Sk); err != nil {
					t.Fatal(err)
				}
				var rnd [32]byte
				if !tc.Deterministic {
					copy(rnd[:], tc.Input.Rnd)
				}
				sig := sk.unsafeSignInternal(tc.Input.Message, rnd)
				if !bytes.Equal(sig, tc.Output.Signature) {
					t.Fatal("signature differs from NIST")
				}
			case "sigVer":
				var pk PublicKey
				if err := pk.UnmarshalBinary(tc.Pk); err != nil {
					t.Fatal(err)
				}
				if unsafeVerifyInternal(&pk, tc.Input.Message, tc.Input.Signature) != tc.Output.TestPassed {
					t.Fatal("verification differs from NIST")
				}
			default:
				t.Fatal("unexpected operation")
			}
		})
	}
}
