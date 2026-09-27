package cryptoutils_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	c "www.gitlablow.com/wave4y/cryptoutils"
)

func TestExtendedHashVectors(t *testing.T) {
	// Fixed abc vectors cross-checked with OpenSSL/Python hashlib.
	tests := []struct {
		name, want string
		method     func(*c.CryptoData) *c.CryptoData
	}{
		{"SHA-224", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7", (*c.CryptoData).Sha224},
		{"SHA384", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7", (*c.CryptoData).Sha384},
		{"SHA-512/224", "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa", (*c.CryptoData).Sha512224},
		{"sha512_256", "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23", (*c.CryptoData).Sha512256},
		{"SHA3-224", "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf", (*c.CryptoData).Sha3_224},
		{"sha3_256", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532", (*c.CryptoData).Sha3_256},
		{"sha3-384", "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25", (*c.CryptoData).Sha3_384},
		{"sha3-512", "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0", (*c.CryptoData).Sha3_512},
		{"blake2b-256", "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319", (*c.CryptoData).Blake2b256},
		{"blake2b384", "6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6c66ba83be64b302d7cba6ce15bb556f4", (*c.CryptoData).Blake2b384},
		{"blake2b", "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923", (*c.CryptoData).Blake2b512},
		{"blake2s", "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982", (*c.CryptoData).Blake2s256},
		{"RIPEMD-160", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc", (*c.CryptoData).Ripemd160},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := c.Init("abc").Hash(tt.name).String(); got != tt.want {
				t.Fatalf("Hash = %s", got)
			}
			if got := tt.method(c.Init("abc")).String(); got != tt.want {
				t.Fatalf("method = %s", got)
			}
			if got := c.Init("abc").HashBytes(tt.name).Hex().String(); got != tt.want {
				t.Fatalf("HashBytes = %s", got)
			}
		})
	}
	for _, tt := range []struct {
		name, want string
		method     func(*c.CryptoData) *c.CryptoData
	}{
		{"keccak256", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", (*c.CryptoData).Keccak256},
		{"keccak512", "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e", (*c.CryptoData).Keccak512},
	} {
		if got := tt.method(c.Init(nil)).String(); got != tt.want {
			t.Errorf("%s = %s", tt.name, got)
		}
		if got := c.Init(nil).Hash("legacy-" + tt.name).String(); got != tt.want {
			t.Errorf("alias %s = %s", tt.name, got)
		}
	}
}

func TestSHAKEVectorsAndBounds(t *testing.T) {
	tests := []struct {
		want        string
		f           func([]byte, int) ([]byte, error)
		method, raw func(*c.CryptoData, int) *c.CryptoData
	}{
		{"7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26", c.SHAKE128, (*c.CryptoData).Shake128, (*c.CryptoData).Shake128Bytes},
		{"46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be", c.SHAKE256, (*c.CryptoData).Shake256, (*c.CryptoData).Shake256Bytes},
	}
	for _, tt := range tests {
		n := len(tt.want) / 2
		got, err := tt.f(nil, n)
		if err != nil || hex.EncodeToString(got) != tt.want {
			t.Fatalf("SHAKE = %x, %v", got, err)
		}
		if tt.method(c.Init(nil), n).String() != tt.want || !bytes.Equal(tt.raw(c.Init(nil), n).Bytes(), got) {
			t.Fatal("SHAKE chain mismatch")
		}
		if zero, err := tt.f(nil, 0); err != nil || len(zero) != 0 {
			t.Fatal("zero output rejected")
		}
		for _, invalid := range []int{-1, c.MaxSHAKEOutput + 1, int(^uint(0) >> 1)} {
			if out, err := tt.f(nil, invalid); err == nil || out != nil {
				t.Fatal("invalid SHAKE length accepted")
			}
			if tt.raw(c.Init("abc"), invalid).Err() == nil {
				t.Fatal("chain lost SHAKE error")
			}
		}
	}
	if !errors.Is(c.Init(nil).Hash("shake128").Err(), c.ErrUnsupportedHash) {
		t.Fatal("Hash accepted variable output without length")
	}
}

func TestGenericHMACVectors(t *testing.T) {
	key, data := bytes.Repeat([]byte{0x0b}, 20), []byte("Hi There")
	for _, tt := range []struct{ name, want string }{
		{"sha512", "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"},
		{"sha3-256", "ba85192310dffa96e2a3a40e69774351140bb7185e1202cdcc917589f95e16bb"},
		{"sm3", "51b00d1fb49832bfb01c3ce27848e59f871d9ba938dc563b338ca964755cce70"},
	} {
		tag, err := c.HMAC(data, key, tt.name)
		if err != nil || hex.EncodeToString(tag) != tt.want {
			t.Fatalf("HMAC %s = %x %v", tt.name, tag, err)
		}
		if c.Init(data).HMAC(key, tt.name).String() != tt.want || !bytes.Equal(c.Init(data).HMACBytes(key, tt.name).Bytes(), tag) {
			t.Fatal("HMAC chain differs")
		}
		if ok, err := c.VerifyHMAC(data, key, tag, tt.name); !ok || err != nil {
			t.Fatal("valid HMAC rejected")
		}
		for _, invalid := range [][]byte{nil, tag[:len(tag)-1], append(append([]byte(nil), tag...), 0)} {
			if ok, err := c.VerifyHMAC(data, key, invalid, tt.name); ok || err != nil {
				t.Fatal("invalid HMAC accepted")
			}
		}
		if ok, _ := c.VerifyHMAC([]byte("changed"), key, tag, tt.name); ok {
			t.Fatal("changed message accepted")
		}
	}
	if out, err := c.HMAC(nil, nil, "unknown"); out != nil || !errors.Is(err, c.ErrUnsupportedHash) {
		t.Fatal("unknown HMAC accepted")
	}
	if ok, err := c.VerifyHMAC(nil, nil, nil, "unknown"); ok || err == nil {
		t.Fatal("unknown verify accepted")
	}
	p := c.Init("abc").HMAC(nil, "unknown")
	first := p.Err()
	p.Shake128(10).Shake256(10).HMACBytes(nil, "sha256").Hash("sha512")
	if first == nil || p.Err() != first || p.Bytes() != nil {
		t.Fatal("sticky error lost")
	}
}
