package set4

import (
	"crypto/sha1"
	"encoding/hex"
	"testing"
)

func GetTag(key, message string) []byte {
	tag := sha1.Sum([]byte(key + message))
	return tag[:]
}

func Test28(t *testing.T) {
	key := "yellow submarine"

	if hex.EncodeToString(GetTag(key, "hello world")) == hex.EncodeToString(GetTag(key, "hello world!")) {
		t.Errorf("MAC tag should be different for different messages")
	}
}
