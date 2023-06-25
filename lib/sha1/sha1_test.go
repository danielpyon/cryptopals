package sha1

import (
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"testing"
)

func TestHardCode(t *testing.T) {
	sum := Sum([]byte("A"))
	result := fmt.Sprintf("%x", sum[:])
	if result != "6dcd4ce23d88e2ee9568ba546c007c63d9131c1b" {
		t.Errorf("wrong checksum!")
	}

	sum = Sum([]byte("hello world"))
	result = fmt.Sprintf("%x", sum[:])
	if result != "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed" {
		t.Errorf("wrong checksum!")
	}
}

func TestRandom(t *testing.T) {
	for i := 0; i < 100; i++ {
		test := make([]byte, 128)
		if _, err := rand.Read(test); err != nil {
			t.Errorf("failed to generate test input")
		}

		actual := Sum(test)
		expected := sha1.Sum(test)

		if len(actual) != len(expected) {
			t.Errorf("wrong sha1 checksum")
		}

		for i := range actual {
			if actual[i] != expected[i] {
				t.Errorf("wrong sha1 checksum")
			}
		}
	}
}
