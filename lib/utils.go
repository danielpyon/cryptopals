package lib

import (
	"errors"
	"fmt"
	"strings"
)

func XorInPlace(dst, src []byte) error {
	length := len(dst)
	if length != len(src) {
		return errors.New("lengths are not equal")
	}
	for i, _ := range dst {
		dst[i] = dst[i] ^ src[i]
	}
	return nil
}

func FillSlice[T any](arr []T, val T) {
	for i := range arr {
		arr[i] = val
	}
}

// Convert byte array to string (note that they're bytes, not runes)
func BytesToString(x []byte) string {
	var sb strings.Builder
	for i := 0; i < len(x); i++ {
		sb.WriteString("%c")
	}
	format_str := sb.String()

	tmp := make([]interface{}, len(x))
	for i, val := range x {
		tmp[i] = val
	}
	return fmt.Sprintf(format_str, tmp...)
}
