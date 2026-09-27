package cryptoutils

import "errors"

var (
	// ErrUnsupportedInput indicates that Init received neither a string nor bytes.
	ErrUnsupportedInput = errors.New("cryptoutils: unsupported input type")
	// ErrUnsupportedHash indicates that a requested digest is not implemented.
	ErrUnsupportedHash = errors.New("cryptoutils: unsupported hash")
)
