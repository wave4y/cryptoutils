// Adaptations for cryptoutils. See ../../../README.md for provenance.
package mldsa65

import (
	"github.com/wave4y/cryptoutils/pqc/internal/reference/sign"
	"github.com/wave4y/cryptoutils/pqc/internal/reference/sign/mldsa/mldsa65/internal"
	"io"
)

// SignToWithRandomness is the FIPS pure signing interface with explicit 32-byte
// randomness. It is internal to cryptoutils and used for testable entropy reads.
func SignToWithRandomness(sk *PrivateKey, msg, ctx []byte, rnd [32]byte, sig []byte) error {
	if len(ctx) > 255 {
		return sign.ErrContextTooLong
	}
	internal.SignTo((*internal.PrivateKey)(sk), func(w io.Writer) {
		_, _ = w.Write([]byte{0, byte(len(ctx))})
		_, _ = w.Write(ctx)
		_, _ = w.Write(msg)
	}, rnd, sig)
	return nil
}
