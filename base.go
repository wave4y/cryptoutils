// Package cryptoutils provides chainable encoding, hashing and encryption helpers.
package cryptoutils

import "fmt"

// CryptoData is a mutable processing chain. It is not safe for concurrent use.
// The first error stops subsequent transformations until Reset is called.
type CryptoData struct {
	data    []byte
	raw     []byte
	key     []byte
	err     error
	initErr error
}

// Init copies a string or byte slice. A nil input represents empty data.
// Unsupported input types are reported by Err and Result.
func Init(src interface{}) *CryptoData {
	p := new(CryptoData)
	switch src := src.(type) {
	case nil:
	case string:
		p.raw = []byte(src)
	case []byte:
		p.raw = cloneBytes(src)
	default:
		p.initErr = fmt.Errorf("%w: %T", ErrUnsupportedInput, src)
	}
	return p.Reset()
}

// SetKey copies key. It does not clear an existing error.
func (p *CryptoData) SetKey(key []byte) {
	p.key = cloneBytes(key)
}

// String returns the current data without changing the chain. On error it
// returns an empty string; use Err or Result to distinguish failure from empty data.
func (p *CryptoData) String() string {
	return string(p.data)
}

// Bytes returns a copy of the current data, or nil if the chain has failed.
func (p *CryptoData) Bytes() []byte {
	return cloneBytes(p.data)
}

// Err returns the first error encountered by the chain.
func (p *CryptoData) Err() error { return p.err }

// Result returns a copy of the current data and any processing error.
func (p *CryptoData) Result() ([]byte, error) {
	if p.err != nil {
		return nil, p.err
	}
	return p.Bytes(), nil
}

// Reset restores the original input and clears processing errors, retaining the
// key. An invalid Init input remains invalid after Reset.
func (p *CryptoData) Reset() *CryptoData {
	p.data = cloneBytes(p.raw)
	p.err = p.initErr
	return p
}

func (p *CryptoData) fail(err error) *CryptoData {
	if p.err == nil && err != nil {
		p.err = err
		p.data = nil
	}
	return p
}

func cloneBytes(src []byte) []byte {
	if src == nil {
		return nil
	}
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}
