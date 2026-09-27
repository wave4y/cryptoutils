package cryptoutils

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// Hex encodes the current bytes as lowercase hexadecimal.
func (p *CryptoData) Hex() *CryptoData {
	if p.err != nil {
		return p
	}
	p.data = []byte(hex.EncodeToString(p.data))
	return p
}

// HexDecode decodes hexadecimal, rejecting malformed or partial input.
func (p *CryptoData) HexDecode() *CryptoData {
	if p.err != nil {
		return p
	}
	data, err := hex.DecodeString(string(p.data))
	if err != nil {
		return p.fail(fmt.Errorf("cryptoutils: hex decode: %w", err))
	}
	p.data = data
	return p
}

// Base64Encode encodes the current bytes using standard padded Base64.
func (p *CryptoData) Base64Encode() *CryptoData {
	if p.err != nil {
		return p
	}
	p.data = []byte(base64.StdEncoding.EncodeToString(p.data))
	return p
}

// Base64Decode decodes standard Base64, rejecting malformed or partial input.
func (p *CryptoData) Base64Decode() *CryptoData {
	if p.err != nil {
		return p
	}
	data, err := base64.StdEncoding.DecodeString(string(p.data))
	if err != nil {
		return p.fail(fmt.Errorf("cryptoutils: base64 decode: %w", err))
	}
	p.data = data
	return p
}
