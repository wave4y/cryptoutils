package utils

import "fmt"

func Str2oct(command string) string {
	var command8 string

	for _, c := range command {
		command8 += fmt.Sprintf("\\%03o", c)
	}
	command8 = fmt.Sprintf("$'%s'", command8)
	return command8
}

func Str2hex(command string) string {
	var command16 string

	for _, c := range command {
		command16 += fmt.Sprintf("\\x%02x", c)
	}
	command16 = fmt.Sprintf("$'%s'", command16)
	return command16
}
