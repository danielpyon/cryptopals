package set4

import (
	"math/rand"
	"strings"

	"github.com/danielpyon/cryptopals/lib"
)

type CtrOracle struct {
	key   []byte
	nonce uint64
}

func (o *CtrOracle) Init() {
	var err error
	o.key, err = lib.GenerateAesKey()
	o.nonce = rand.Uint64()

	if err != nil {
		panic("Could not generate AES key")
	}
}

func (o *CtrOracle) Encrypt(userData string) []byte {
	pre := "comment1=cooking%20MCs;userdata="
	post := ";comment2=%20like%20a%20pound%20of%20bacon"

	// sanitize user input
	userData = strings.ReplaceAll(userData, "=", "")
	userData = strings.ReplaceAll(userData, ";", "")

	plaintext := lib.PadPkcs7([]byte(pre+userData+post), 16)

	var ciphertext []byte
	ciphertext, err := lib.EncryptAesCtr(plaintext, o.key, o.nonce)
	if err != nil {
		panic("Could not encrypt plaintext")
	}

	return ciphertext
}

func (o *CtrOracle) IsAdmin(ciphertext []byte) bool {
	plaintext, err := lib.DecryptAesCtr(ciphertext, o.key, o.nonce)
	if err != nil {
		panic("Could not decrypt ciphertext")
	}

	unpadded, err := lib.UnpadPkcs7(plaintext)
	if err != nil {
		return false
	} else {
		return strings.Contains(lib.BytesToString(unpadded), ";admin=true;")
	}
}
