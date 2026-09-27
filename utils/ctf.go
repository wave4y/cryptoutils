package utils

import "strings"

// Str2oct encodes the string's bytes as octal escapes in Bash ANSI-C quotes.
func Str2oct(command string) string {
	var result strings.Builder
	result.Grow(4*len(command) + 3)
	result.WriteString("$'")
	for i := 0; i < len(command); i++ {
		c := command[i]
		result.WriteByte('\\')
		result.WriteByte('0' + c>>6)
		result.WriteByte('0' + (c>>3)&7)
		result.WriteByte('0' + c&7)
	}
	result.WriteByte('\'')
	return result.String()
}

// Str2hex encodes the string's bytes as hexadecimal escapes in Bash ANSI-C quotes.
func Str2hex(command string) string {
	const digits = "0123456789abcdef"
	var result strings.Builder
	result.Grow(4*len(command) + 3)
	result.WriteString("$'")
	for i := 0; i < len(command); i++ {
		c := command[i]
		result.WriteString("\\x")
		result.WriteByte(digits[c>>4])
		result.WriteByte(digits[c&15])
	}
	result.WriteByte('\'')
	return result.String()
}
