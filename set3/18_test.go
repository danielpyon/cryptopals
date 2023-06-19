package set3

import (
	b64 "encoding/base64"
	"fmt"
	"testing"

	"github.com/danielpyon/cryptopals/lib"
)

func Test18(t *testing.T) {
	ciphertext, _ := b64.StdEncoding.DecodeString("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	plaintext, err := lib.DecryptAesCtr(ciphertext, []byte("YELLOW SUBMARINE"), 0)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(lib.BytesToString(plaintext))
}
