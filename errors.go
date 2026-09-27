package cryptoutils

import (
	"errors"

	"github.com/wave4y/cryptoutils/internal/digest"
)

var (
	// ErrUnsupportedInput indicates that Init received neither a string nor bytes.
	ErrUnsupportedInput = errors.New("cryptoutils: unsupported input type")
	// ErrUnsupportedHash indicates that a requested digest is not implemented.
	ErrUnsupportedHash = digest.ErrUnsupportedHash
)
