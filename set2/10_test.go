package set2

import (
	"fmt"
	"testing"

	"github.com/danielpyon/cryptopals/lib"
	"github.com/danielpyon/cryptopals/set1"
)

func Test10(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")

	// given test case
	ciphertext, err := set1.ReadBase64EncodedFile("10.txt")
	if err != nil {
		t.Errorf("Error in reading ciphertext file")
	}

	plaintext, err := lib.DecryptAesCbc(ciphertext, key)
	if err != nil {
		t.Errorf("Error in decryption")
	}

	plaintextString := lib.BytesToString(plaintext)
	fmt.Println(plaintextString)
}
