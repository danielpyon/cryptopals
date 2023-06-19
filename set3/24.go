package set3

import (
	"github.com/danielpyon/cryptopals/lib"
)

func SliceEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func FindKey(ciphertext []byte) uint16 {
	desiredPlaintext := make([]byte, 14)
	lib.FillSlice(desiredPlaintext, 0x41)

	i := uint16(0)
	found := false
	for ; i < 0xffff; i++ {
		plaintext, err := lib.DecryptMT19937(ciphertext, i)
		if err != nil {
			panic("failed to decrypt")
		}

		if SliceEq(plaintext[len(plaintext)-14:], desiredPlaintext) {
			found = true
			break
		}
	}

	if !found {
		panic("couldn't find key!")
	}

	return i
}

func TokenFromMT19937(token []byte) bool {
	n := len(token)

	i := uint16(0)
	for ; i < 0xffff; i++ {
		zeros := make([]byte, n)
		lib.FillSlice(zeros, 0)

		guess, err := lib.EncryptMT19937(zeros, i)
		if err != nil {
			panic("failed to decrypt")
		}

		if SliceEq(token, guess) {
			return true
		}
	}

	return false
}
