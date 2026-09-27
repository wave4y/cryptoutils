package rsactf

import (
	"bytes"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
)

const (
	maxPublicDERSize = 64 * 1024
	maxPublicPEMSize = 128 * 1024
)

var rsaEncryptionOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}

// ParsePublicKeyDER parses one PKCS#1 RSAPublicKey or PKIX SubjectPublicKeyInfo.
// It accepts n > 1 and arbitrary-size e > 0, following EncryptRaw's integer
// rules rather than padded RSA key policy. PKIX must identify rsaEncryption;
// its parameters may be NULL or absent. Input is limited to 64 KiB. Trailing
// data, extra fields, and malformed encodings return ErrInvalidInput.
func ParsePublicKeyDER(der []byte) (*PublicParameters, error) {
	return parsePublicKeyDER(der, "")
}

// ParsePublicKeyPEM parses one RSA PUBLIC KEY (PKCS#1) or PUBLIC KEY (PKIX)
// block with no PEM headers. Only surrounding whitespace is allowed; extra
// blocks or text are rejected. The input is limited to 128 KiB and the decoded
// DER to 64 KiB. The integer and algorithm rules match ParsePublicKeyDER.
func ParsePublicKeyPEM(data []byte) (*PublicParameters, error) {
	if len(data) > maxPublicPEMSize {
		return nil, ErrInvalidInput
	}
	data = bytes.TrimSpace(data)
	var kind string
	for _, candidate := range []string{"RSA PUBLIC KEY", "PUBLIC KEY"} {
		if bytes.HasPrefix(data, []byte("-----BEGIN "+candidate+"-----")) {
			kind = candidate
			break
		}
	}
	// pem.Decode can skip leading malformed blocks or arbitrary text. Require
	// exactly one BEGIN marker and a recognized block at the start instead.
	if kind == "" || bytes.Count(data, []byte("-----BEGIN ")) != 1 {
		return nil, ErrInvalidInput
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != kind || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrInvalidInput
	}
	return parsePublicKeyDER(block.Bytes, kind)
}

func parsePublicKeyDER(der []byte, kind string) (*PublicParameters, error) {
	if len(der) == 0 || len(der) > maxPublicDERSize {
		return nil, ErrInvalidInput
	}
	fields, ok := sequenceFields(der)
	if !ok || len(fields) != 2 {
		return nil, ErrInvalidInput
	}
	if isASN1(fields[0], asn1.TagInteger, false) {
		if kind == "PUBLIC KEY" {
			return nil, ErrInvalidInput
		}
		return parsePublicIntegers(fields)
	}
	if kind == "RSA PUBLIC KEY" || !isASN1(fields[0], asn1.TagSequence, true) ||
		!isASN1(fields[1], asn1.TagBitString, false) {
		return nil, ErrInvalidInput
	}
	algorithm, ok := sequenceFields(fields[0].FullBytes)
	if !ok || len(algorithm) < 1 || len(algorithm) > 2 {
		return nil, ErrInvalidInput
	}
	var oid asn1.ObjectIdentifier
	if !isASN1(algorithm[0], asn1.TagOID, false) {
		return nil, ErrInvalidInput
	}
	if rest, err := asn1.Unmarshal(algorithm[0].FullBytes, &oid); err != nil || len(rest) != 0 || !oid.Equal(rsaEncryptionOID) {
		return nil, ErrInvalidInput
	}
	if len(algorithm) == 2 && (!isASN1(algorithm[1], asn1.TagNull, false) || len(algorithm[1].Bytes) != 0) {
		return nil, ErrInvalidInput
	}
	var bits asn1.BitString
	if rest, err := asn1.Unmarshal(fields[1].FullBytes, &bits); err != nil || len(rest) != 0 || bits.BitLength != len(bits.Bytes)*8 {
		return nil, ErrInvalidInput
	}
	public, ok := sequenceFields(bits.Bytes)
	if !ok || len(public) != 2 {
		return nil, ErrInvalidInput
	}
	return parsePublicIntegers(public)
}

func parsePublicIntegers(fields []asn1.RawValue) (*PublicParameters, error) {
	values := make([]*big.Int, 2)
	for i, field := range fields {
		if !isASN1(field, asn1.TagInteger, false) {
			return nil, ErrInvalidInput
		}
		if rest, err := asn1.Unmarshal(field.FullBytes, &values[i]); err != nil || len(rest) != 0 {
			return nil, ErrInvalidInput
		}
	}
	if !validModulus(values[0]) || !validExponent(values[1]) {
		return nil, ErrInvalidInput
	}
	return &PublicParameters{N: values[0], E: values[1]}, nil
}

// Decode each field explicitly: unmarshalling into a struct would silently
// accept extra fields in an otherwise well-formed ASN.1 SEQUENCE.
func sequenceFields(der []byte) ([]asn1.RawValue, bool) {
	var sequence asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &sequence); err != nil || len(rest) != 0 || !isASN1(sequence, asn1.TagSequence, true) {
		return nil, false
	}
	var fields []asn1.RawValue
	for remaining := sequence.Bytes; len(remaining) > 0; {
		var field asn1.RawValue
		rest, err := asn1.Unmarshal(remaining, &field)
		if err != nil || len(fields) == 3 {
			return nil, false
		}
		fields = append(fields, field)
		remaining = rest
	}
	return fields, true
}

func isASN1(value asn1.RawValue, tag int, compound bool) bool {
	return value.Class == asn1.ClassUniversal && value.Tag == tag && value.IsCompound == compound
}
