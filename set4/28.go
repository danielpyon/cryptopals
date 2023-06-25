package set4

import (
	"crypto/sha1"
)

func GetTag(key, message string) []byte {
	tag := sha1.Sum([]byte(key + message))
	return tag[:]
}
