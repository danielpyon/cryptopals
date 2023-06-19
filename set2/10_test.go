package set2

import (
	"fmt"
	"testing"

	"github.com/danielpyon/cryptopals/lib"
	"github.com/danielpyon/cryptopals/set1"
)

func Test10(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")

	/*
		ciphertext, err := EncryptAesCbc([]byte("AAAAAAAAAAAAAAAA"), key)

		if err != nil {
			fmt.Println("error: ", err)
			return
		}

		fmt.Println(ciphertext)
	*/

	// given test case
	ciphertext, err := set1.ReadBase64EncodedFile("10.txt")
	plaintext, err := lib.DecryptAesCbc(ciphertext, key)
	if err != nil {
		t.Errorf("Error in decryption")
	}

	plaintextString := lib.BytesToString(plaintext)
	fmt.Println(plaintextString)
}
