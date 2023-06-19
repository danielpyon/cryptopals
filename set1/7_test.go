package set1

import (
	"fmt"
	"testing"

	"github.com/danielpyon/cryptopals/lib"
)

func Test7(t *testing.T) {
	ciphertext, err := ReadBase64EncodedFile("7.txt")
	if err != nil {
		panic("could not read file!")
	}

	key := []byte("YELLOW SUBMARINE")
	plaintext, _ := lib.DecryptAesEcb(ciphertext, key)
	fmt.Println(lib.BytesToString(plaintext))
}
