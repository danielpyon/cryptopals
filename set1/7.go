package set1

import (
	"fmt"

	"github.com/danielpyon/cryptopals/lib"
)

func Test7() {
	ciphertext, err := lib.ReadBase64EncodedFile("7.txt")
	if err != nil {
		panic("could not read file!")
	}

	key := []byte("YELLOW SUBMARINE")
	plaintext, _ := lib.DecryptAesEcb(ciphertext, key)
	fmt.Println(lib.BytesToString(plaintext))
}
