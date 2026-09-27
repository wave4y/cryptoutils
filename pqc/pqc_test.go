package pqc

import (
	"bytes"
	"errors"
	"golang.org/x/crypto/sha3"
	"io"
	"testing"
)

type brokenRandom struct{ err error }

func (r brokenRandom) Read([]byte) (int, error) { return 0, r.err }

type oneByteReader struct{ source io.Reader }

func (r oneByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.source.Read(p)
}

func TestMLKEMInputBoundaries(t *testing.T) {
	wantErr := errors.New("entropy unavailable")
	if _, _, err := GenerateMLKEM(MLKEM768, brokenRandom{wantErr}); !errors.Is(err, wantErr) {
		t.Fatalf("entropy error=%v", err)
	}
	if _, _, err := GenerateMLKEM("", nil); !errors.Is(err, ErrParameter) {
		t.Fatalf("parameter=%v", err)
	}
	if _, _, err := DeriveMLKEM(MLKEM768, make([]byte, 63)); !errors.Is(err, ErrSeed) {
		t.Fatalf("seed=%v", err)
	}
	if _, _, err := EncapsulateMLKEM(nil, nil); !errors.Is(err, ErrKey) {
		t.Fatalf("nil public key=%v", err)
	}
	if _, err := DecapsulateMLKEM(new(MLKEMPrivateKey), nil); !errors.Is(err, ErrKey) {
		t.Fatalf("zero private key=%v", err)
	}
	if (*MLKEMPublicKey)(nil).Bytes() != nil || (*MLKEMPrivateKey)(nil).Bytes() != nil {
		t.Fatal("nil key serialization")
	}
	for _, parameter := range []KEMParameter{MLKEM512, MLKEM768, MLKEM1024} {
		t.Run(string(parameter), func(t *testing.T) {
			pk, sk, err := GenerateMLKEM(parameter, oneByteReader{bytes.NewReader(make([]byte, 64))})
			if err != nil {
				t.Fatal(err)
			}
			pkBytes, skBytes := pk.Bytes(), sk.Bytes()
			if _, err := ParseMLKEMPublicKey(parameter, pkBytes[:len(pkBytes)-1]); !errors.Is(err, ErrKey) {
				t.Fatalf("short public key=%v", err)
			}
			if _, err := ParseMLKEMPrivateKey(parameter, skBytes[:len(skBytes)-1]); !errors.Is(err, ErrKey) {
				t.Fatalf("short private key=%v", err)
			}
			bad := append([]byte{}, pkBytes...)
			bad[0] = 255
			bad[1] |= 15
			if _, err := ParseMLKEMPublicKey(parameter, bad); !errors.Is(err, ErrKey) {
				t.Fatalf("noncanonical public key=%v", err)
			}
			bad = append([]byte{}, skBytes...)
			bad[len(bad)-64] ^= 1
			if _, err := ParseMLKEMPrivateKey(parameter, bad); !errors.Is(err, ErrKey) {
				t.Fatalf("inconsistent private key=%v", err)
			}
			if _, _, err := EncapsulateMLKEM(pk, brokenRandom{wantErr}); !errors.Is(err, wantErr) {
				t.Fatalf("encapsulate entropy=%v", err)
			}
			ciphertext, secret, err := EncapsulateMLKEM(pk, bytes.NewReader(make([]byte, 32)))
			if err != nil {
				t.Fatal(err)
			}
			pkParsed, err := ParseMLKEMPublicKey(parameter, pkBytes)
			if err != nil {
				t.Fatal(err)
			}
			skParsed, err := ParseMLKEMPrivateKey(parameter, skBytes)
			if err != nil {
				t.Fatal(err)
			}
			if pkParsed.Parameter() != parameter || skParsed.Parameter() != parameter {
				t.Fatal("parameter lost")
			}
			recovered, err := DecapsulateMLKEM(skParsed, ciphertext)
			if err != nil || !bytes.Equal(secret, recovered) {
				t.Fatal("roundtrip")
			}
			if _, err := DecapsulateMLKEM(sk, ciphertext[:len(ciphertext)-1]); err == nil {
				t.Fatal("accepted short ciphertext")
			}
			ciphertext[0] ^= 1
			rejected, err := DecapsulateMLKEM(sk, ciphertext)
			if err != nil || bytes.Equal(secret, rejected) {
				t.Fatal("implicit rejection failed")
			}
			rejected2, err := DecapsulateMLKEM(sk, ciphertext)
			if err != nil || !bytes.Equal(rejected, rejected2) {
				t.Fatal("implicit rejection must be deterministic")
			}
			pkBytes[0] ^= 1
			skBytes[0] ^= 1
			if bytes.Equal(pk.Bytes(), pkBytes) || bytes.Equal(sk.Bytes(), skBytes) {
				t.Fatal("serialization leaked mutable key state")
			}
		})
	}
}

func TestSignatureInputBoundaries(t *testing.T) {
	wantErr := errors.New("entropy unavailable")
	for _, parameter := range []SignatureParameter{MLDSA44, MLDSA65, MLDSA87, SLHDSASHA2128f, SLHDSASHAKE128f} {
		t.Run(string(parameter), func(t *testing.T) {
			if _, _, err := GenerateSignatureKey(parameter, brokenRandom{wantErr}); !errors.Is(err, wantErr) {
				t.Fatalf("keygen entropy=%v", err)
			}
			pk, sk, err := GenerateSignatureKey(parameter, nil)
			if err != nil {
				t.Fatal(err)
			}
			message, context := []byte("signed message"), []byte("domain")
			if _, err := Sign(parameter, sk, message, context, brokenRandom{wantErr}); !errors.Is(err, wantErr) {
				t.Fatalf("sign entropy=%v", err)
			}
			signature, err := Sign(parameter, sk, message, context, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := Verify(parameter, pk, message, signature, context); err != nil {
				t.Fatal(err)
			}
			if err := Verify(parameter, pk, message, signature, []byte("other")); !errors.Is(err, ErrVerification) {
				t.Fatalf("wrong context=%v", err)
			}
			if err := Verify(parameter, pk, []byte("tampered"), signature, context); !errors.Is(err, ErrVerification) {
				t.Fatalf("wrong message=%v", err)
			}
			signature[0] ^= 1
			if err := Verify(parameter, pk, message, signature, context); !errors.Is(err, ErrVerification) {
				t.Fatalf("tampered signature=%v", err)
			}
			if err := Verify(parameter, pk, message, signature[:len(signature)-1], context); !errors.Is(err, ErrVerification) {
				t.Fatalf("short signature=%v", err)
			}
			if err := Verify(parameter, pk[:len(pk)-1], message, signature, context); !errors.Is(err, ErrKey) {
				t.Fatalf("short public key=%v", err)
			}
			if _, err := Sign(parameter, sk[:len(sk)-1], message, context, nil); !errors.Is(err, ErrKey) {
				t.Fatalf("short private key=%v", err)
			}
			if _, err := Sign(parameter, sk, message, make([]byte, 256), nil); !errors.Is(err, ErrContext) {
				t.Fatalf("long context=%v", err)
			}
			if err := Verify(parameter, pk, message, signature, make([]byte, 256)); !errors.Is(err, ErrContext) {
				t.Fatalf("long verify context=%v", err)
			}
			a, err := SignDeterministic(parameter, sk, message, nil)
			if err != nil {
				t.Fatal(err)
			}
			b, err := SignDeterministic(parameter, sk, message, []byte{})
			if err != nil || !bytes.Equal(a, b) {
				t.Fatal("deterministic signatures differ")
			}
		})
	}
	if _, _, err := GenerateSignatureKey("", nil); !errors.Is(err, ErrParameter) {
		t.Fatalf("invalid parameter=%v", err)
	}
	if _, _, err := DeriveSignatureKey(MLDSA65, nil); !errors.Is(err, ErrSeed) {
		t.Fatalf("invalid seed=%v", err)
	}
	if _, err := Sign("", nil, nil, nil, nil); !errors.Is(err, ErrParameter) {
		t.Fatalf("invalid sign parameter=%v", err)
	}
	if err := Verify("", nil, nil, nil, nil); !errors.Is(err, ErrParameter) {
		t.Fatalf("invalid verify parameter=%v", err)
	}
}

func TestMalformedMLDSAPrivateKeys(t *testing.T) {
	for _, parameter := range []SignatureParameter{MLDSA44, MLDSA65, MLDSA87} {
		t.Run(string(parameter), func(t *testing.T) {
			_, sk, err := GenerateSignatureKey(parameter, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, offset := range []int{0, 64, 128, len(sk) - 1} {
				bad := append([]byte{}, sk...)
				bad[offset] ^= 255
				if _, err := SignDeterministic(parameter, bad, []byte("message"), nil); !errors.Is(err, ErrKey) {
					t.Fatalf("corrupt private key at %d=%v", offset, err)
				}
			}
			if _, err := SignDeterministic(parameter, make([]byte, len(sk)), nil, nil); !errors.Is(err, ErrKey) {
				t.Fatalf("zero private key=%v", err)
			}
		})
	}
}

func TestSLHDSAShortRandomReads(t *testing.T) {
	parameter := SLHDSASHA2128f
	seed := make([]byte, 48)
	pk, sk, err := GenerateSignatureKey(parameter, oneByteReader{bytes.NewReader(seed)})
	if err != nil {
		t.Fatal(err)
	}
	pk2, sk2, err := DeriveSignatureKey(parameter, seed)
	if err != nil || !bytes.Equal(pk, pk2) || !bytes.Equal(sk, sk2) {
		t.Fatal("short read keygen")
	}
	signature, err := Sign(parameter, sk, nil, nil, oneByteReader{bytes.NewReader(make([]byte, 16))})
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(parameter, pk, nil, signature, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := Sign(parameter, sk, nil, nil, bytes.NewReader(make([]byte, 15))); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short entropy=%v", err)
	}
}

func TestNoncanonicalMLKEMExpandedKey(t *testing.T) {
	for _, parameter := range []KEMParameter{MLKEM512, MLKEM768, MLKEM1024} {
		pk, sk, err := GenerateMLKEM(parameter, nil)
		if err != nil {
			t.Fatal(err)
		}
		encoded := sk.Bytes()
		offset := len(encoded) - len(pk.Bytes()) - 64
		encoded[offset] = 255
		encoded[offset+1] |= 15
		digest := sha3.Sum256(encoded[offset : len(encoded)-64])
		copy(encoded[len(encoded)-64:], digest[:])
		if _, err := ParseMLKEMPrivateKey(parameter, encoded); !errors.Is(err, ErrKey) {
			t.Fatalf("%s noncanonical embedded key=%v", parameter, err)
		}
		encoded = sk.Bytes()
		encoded[0] = 255
		encoded[1] |= 15
		if _, err := ParseMLKEMPrivateKey(parameter, encoded); !errors.Is(err, ErrKey) {
			t.Fatalf("%s noncanonical secret coefficients=%v", parameter, err)
		}
	}
}

func TestInconsistentSLHDSAKey(t *testing.T) {
	for _, parameter := range []SignatureParameter{SLHDSASHA2128f, SLHDSASHAKE128f} {
		_, sk, err := GenerateSignatureKey(parameter, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, offset := range []int{0, len(sk) - 1} {
			bad := append([]byte{}, sk...)
			bad[offset] ^= 1
			if _, err := SignDeterministic(parameter, bad, []byte("message"), nil); !errors.Is(err, ErrKey) {
				t.Fatalf("inconsistent SLH key at %d=%v", offset, err)
			}
		}
	}
}

func TestOversizedMessage(t *testing.T) {
	message := make([]byte, MaxMessageSize+1)
	if _, err := Sign(MLDSA65, nil, message, nil, nil); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("oversized sign=%v", err)
	}
	if err := Verify(MLDSA65, nil, message, nil, nil); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("oversized verify=%v", err)
	}
}
