package bn256

import (
	"encoding/hex"
	"testing"
)

func TestG1RejectsNonCanonicalCoordinates(t *testing.T) {
	modulus, _ := hex.DecodeString("b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457d")
	for _, xy := range [][]byte{append(append([]byte(nil), modulus...), modulus...), append(modulus, make([]byte, 32)...), append(make([]byte, 32), modulus...)} {
		if _, err := new(G1).Unmarshal(xy); err == nil {
			t.Fatal("accepted coordinate >= p")
		}
	}
	if _, err := new(G1).UnmarshalCompressed(append([]byte{2}, modulus...)); err == nil {
		t.Fatal("accepted compressed x >= p")
	}
}
