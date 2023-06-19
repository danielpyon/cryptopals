package set2

import (
	"fmt"
	"testing"

	"github.com/danielpyon/cryptopals/lib"
)

func Test13(t *testing.T) {
	key, err := lib.GenerateAesKey()
	if err != nil {
		panic(err)
	}

	// normally, you have something like this:
	// ciphertext := AES_Encrypt_ECB( Pad("email=foo@bar.com&uid=10&role=user"), key )
	// plaintext := Unpad( AES_Decrypt_ECB( ciphertext, key ))
	// profile := parseKV(plaintext)

	// if you make an email of the right length, the role is isolated in its own block
	// the dividers are block boundaries
	// we take the first two blocks of this ciphertext:
	// email=AAAAA@AAA. | com&uid=10&role= | user\x0c...\x0c
	c1 := EncryptProfile("AAAAA@AAA.com", key)

	// then append the second block of this ciphertext to it
	// email=AAAAA@AAAA | admin\x0b...\x0b | .com&uid=10&role | =user\x0b...\x0b
	c2 := EncryptProfile("AAAAA@AAAAadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b.com", key)

	// the result is:
	// email=AAAAA@AAA. | com&uid=10&role= | admin\x0b...\x0b
	c3 := append(c1[:32], c2[16:32]...)

	// using only EncryptProfile, make a profile with role=admin
	if Check(c3, key) {
		fmt.Println("succeeded")
	} else {
		fmt.Println("failed")
	}
}
