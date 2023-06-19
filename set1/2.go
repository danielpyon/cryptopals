package set1

import "errors"

func Xor(a, b []byte) ([]byte, error) {
	length := len(a)
	if length != len(b) {
		return nil, errors.New("lengths are not equal")
	}

	c := make([]byte, length)
	for i := 0; i < length; i++ {
		c[i] = a[i] ^ b[i]
	}

	return c, nil
}
