package cryptoutils_test

import (
	"bytes"
	c "github.com/wave4y/cryptoutils"
	"testing"
)

func TestEncodingRoundTrips(t *testing.T) {
	for _, src := range [][]byte{nil, {}, []byte("中文🙂"), {0, 1, 127, 128, 255}} {
		if out, err := c.Init(src).Hex().HexDecode().Result(); err != nil || !bytes.Equal(out, src) {
			t.Fatalf("hex = %x, %v", out, err)
		}
		if out, err := c.Init(src).Base64Encode().Base64Decode().Result(); err != nil || !bytes.Equal(out, src) {
			t.Fatalf("base64 = %x, %v", out, err)
		}
	}
}
