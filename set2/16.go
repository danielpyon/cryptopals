package set2

import (
	"fmt"
	"strings"
	"testing"

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

func Test16(t *testing.T) {
	fmt.Println("[+] === chall 16 ===")

	o := CbcOracle{}
	o.Init()
	ct := o.Encrypt("AAAAAAAAAAAAAAAA:admin<true:AAAA")

	// the ciphertext looks like this:
	// init-vector comment1=cooking %20MCs;userdata= AAAAAAAAAAAAAAAA :admin<true:AAAA ;comment2=%20lik e%20a%20pound%20 of%20bacon\x06\x06\x06\x06\x06\x06
	// note that instead of ";admin=true;", we have ":admin<true:"
	// this is because we will flip the corresponding bits

	// flip bits
	block := 3 // we must modify the PREVIOUS block
	ct[block*16] ^= 1
	ct[block*16+6] ^= 1
	ct[block*16+11] ^= 1

	if o.IsAdmin(ct) {
		fmt.Println("success!")
	} else {
		fmt.Println("fail!")
	}
}
