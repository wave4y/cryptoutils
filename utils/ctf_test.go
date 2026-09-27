package utils_test

import (
	"strconv"
	"testing"

	"www.gitlablow.com/wave4y/cryptoutils/utils"
)

func TestStringEscapes(t *testing.T) {
	tests := []struct {
		name, input, octal, hex string
	}{
		{"empty", "", "$''", "$''"},
		{"ASCII and quoting", "a'\\\n", `$'\141\047\134\012'`, `$'\x61\x27\x5c\x0a'`},
		{"UTF-8", "中文🙂", `$'\344\270\255\346\226\207\360\237\231\202'`, `$'\xe4\xb8\xad\xe6\x96\x87\xf0\x9f\x99\x82'`},
		{"invalid UTF-8", "\xff\x80", `$'\377\200'`, `$'\xff\x80'`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := utils.Str2oct(tt.input); got != tt.octal {
				t.Errorf("Str2oct(%q) = %q; want %q", tt.input, got, tt.octal)
			}
			if got := utils.Str2hex(tt.input); got != tt.hex {
				t.Errorf("Str2hex(%q) = %q; want %q", tt.input, got, tt.hex)
			}
		})
	}
}

func TestStringEscapesPreserveAllBytes(t *testing.T) {
	input := make([]byte, 256)
	for i := range input {
		input[i] = byte(i)
	}
	for name, encode := range map[string]func(string) string{
		"octal": utils.Str2oct,
		"hex":   utils.Str2hex,
	} {
		t.Run(name, func(t *testing.T) {
			encoded := encode(string(input))
			if len(encoded) != 4*len(input)+3 || encoded[:2] != "$'" || encoded[len(encoded)-1] != '\'' {
				t.Fatalf("unexpected escape format: %q", encoded)
			}
			// Go and Bash use the same byte values for these fixed-width escapes.
			decoded, err := strconv.Unquote(`"` + encoded[2:len(encoded)-1] + `"`)
			if err != nil {
				t.Fatal(err)
			}
			if decoded != string(input) {
				t.Fatal("escapes do not preserve input bytes")
			}
		})
	}
}
