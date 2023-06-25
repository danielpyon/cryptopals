package set4

import (
	"encoding/hex"
	"testing"
)

func Test28(t *testing.T) {
	key := "yellow submarine"

	if hex.EncodeToString(GetTag(key, "hello world")) == hex.EncodeToString(GetTag(key, "hello world!")) {
		t.Errorf("MAC tag should be different for different messages")
	}
}
