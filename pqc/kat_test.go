package pqc

import (
	"bytes"
	"fmt"
	"testing"
	"www.gitlablow.com/wave4y/cryptoutils/pqc/internal/kat"
)

func TestMLKEMNISTACVP(t *testing.T) {
	for _, tc := range kat.Load(t, "ML-KEM") {
		t.Run(fmt.Sprintf("%s/%s/%d", tc.Parameter, tc.Operation, tc.Input.TcID), func(t *testing.T) {
			parameter := KEMParameter(tc.Parameter)
			switch tc.Operation {
			case "keyGen":
				seed := append(append([]byte{}, tc.Input.D...), tc.Input.Z...)
				pk, sk, err := DeriveMLKEM(parameter, seed)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(pk.Bytes(), tc.Output.Ek) || !bytes.Equal(sk.Bytes(), tc.Output.Dk) {
					t.Fatal("key encoding differs from NIST")
				}
			case "encapDecap":
				if tc.TestType == "AFT" {
					pk, err := ParseMLKEMPublicKey(parameter, tc.Input.Ek)
					if err != nil {
						t.Fatal(err)
					}
					ciphertext, secret, err := EncapsulateMLKEM(pk, bytes.NewReader(tc.Input.M))
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(ciphertext, tc.Output.C) || !bytes.Equal(secret, tc.Output.K) {
						t.Fatal("encapsulation differs from NIST")
					}
				} else {
					sk, err := ParseMLKEMPrivateKey(parameter, tc.Dk)
					if err != nil {
						t.Fatal(err)
					}
					secret, err := DecapsulateMLKEM(sk, tc.Input.C)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(secret, tc.Output.K) {
						t.Fatal("decapsulation differs from NIST")
					}
				}
			default:
				t.Fatal("unknown operation")
			}
		})
	}
}

func TestSignatureNISTACVP(t *testing.T) {
	for _, family := range []string{"ML-DSA", "SLH-DSA"} {
		for _, tc := range kat.Load(t, family) {
			// ML-DSA's NIST samples exercise the internal interface; those signature
			// tests reside alongside the reference cores without exposing internal APIs.
			if family == "ML-DSA" && tc.Operation != "keyGen" {
				continue
			}
			t.Run(fmt.Sprintf("%s/%s/%d", tc.Parameter, tc.Operation, tc.Input.TcID), func(t *testing.T) {
				parameter := SignatureParameter(tc.Parameter)
				switch tc.Operation {
				case "keyGen":
					seed := []byte(tc.Input.Seed)
					if family == "SLH-DSA" {
						seed = append(append(append([]byte{}, tc.Input.SkSeed...), tc.Input.SkPrf...), tc.Input.PkSeed...)
					}
					pk, sk, err := DeriveSignatureKey(parameter, seed)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(pk, tc.Output.Pk) || !bytes.Equal(sk, tc.Output.Sk) {
						t.Fatal("key encoding differs from NIST")
					}
				case "sigGen":
					signature, err := SignDeterministic(parameter, tc.Input.Sk, tc.Input.Message, tc.Input.Context)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(signature, tc.Output.Signature) {
						t.Fatal("signature differs from NIST")
					}
					// SLH expanded private encodings end with the public key.
					pk := tc.Input.Sk[len(tc.Input.Sk)/2:]
					if err := Verify(parameter, pk, tc.Input.Message, signature, tc.Input.Context); err != nil {
						t.Fatal(err)
					}
				case "sigVer":
					err := Verify(parameter, tc.Input.Pk, tc.Input.Message, tc.Input.Signature, tc.Input.Context)
					if (err == nil) != tc.Output.TestPassed {
						t.Fatalf("verify=%v, want valid=%v", err, tc.Output.TestPassed)
					}
				default:
					t.Fatal("unknown operation")
				}
			})
		}
	}
}
