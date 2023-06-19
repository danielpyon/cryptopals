package set2

import (
	"strings"

	"github.com/danielpyon/cryptopals/lib"
)

type CbcOracle struct {
	key []byte
}

func (o *CbcOracle) Init() {
	var err error
	o.key, err = lib.GenerateAesKey()

	if err != nil {
		panic("Could not generate AES key")
	}
}

func (o *CbcOracle) Encrypt(userData string) []byte {
	pre := "comment1=cooking%20MCs;userdata="
	post := ";comment2=%20like%20a%20pound%20of%20bacon"

	// sanitize user input
	userData = strings.ReplaceAll(userData, "=", "")
	userData = strings.ReplaceAll(userData, ";", "")

	plaintext := lib.PadPkcs7([]byte(pre+userData+post), 16)

	var ciphertext []byte
	ciphertext, err := lib.EncryptAesCbc(plaintext, o.key)
	if err != nil {
		panic("Could not encrypt plaintext")
	}

	return ciphertext
}

func (o *CbcOracle) IsAdmin(ciphertext []byte) bool {
	plaintext, err := lib.DecryptAesCbc(ciphertext, o.key)
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
