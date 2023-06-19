package set2

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/danielpyon/cryptopals/lib"
)

func Test9(t *testing.T) {
	padded := lib.PadPkcs7([]byte("YELLOW SUBMARINE"), 20)
	fmt.Println(hex.EncodeToString(padded))

	ciphertext, _ := lib.EncryptAesEcb([]byte("hello world!AAAA"), []byte("YELLOW SUBMARINE"))
	plaintext, _ := lib.DecryptAesEcb(ciphertext, []byte("YELLOW SUBMARINE"))

	fmt.Println(lib.BytesToString(plaintext))
}
