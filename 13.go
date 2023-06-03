package main

import (
	"fmt"
	"strings"
	"encoding/json"
)

func ProfileFor(email string) string {
	// delete &, = from email
	email = strings.Replace(email, "&", "", -1)
	email = strings.Replace(email, "=", "", -1)
	encoded := "email=" + email + "&uid=10&role=user"
	return encoded
}

func EncryptProfile(email string, key []byte) []byte {
	encoded := []byte(ProfileFor(email))
	padded := PadPkcs7(encoded, 16)

	encryptedProfile, err := EncryptAesEcb(padded, key)
	if err != nil {
		panic(err)
	}

	return encryptedProfile
}

func DecryptProfile(encryptedProfile, key []byte) []byte {
	profile, err := DecryptAesEcb(encryptedProfile, key)
	if err != nil {
		panic(err)
	}

	unpadded, err := UnpadPkcs7(profile)
	if err != nil {
		panic(err)
	}

	profileStr := BytesToString(unpadded)
	kvs, err := ParseKeyValue(profileStr)
	if err != nil {
		panic(err)
	}

	return kvs
}


// check if we have successfully gotten admin role
func Check(profile, key []byte) bool {
	decrypted := DecryptProfile(profile, key)
	
	var decoded map[string]interface{}
	if err := json.Unmarshal(decrypted, &decoded); err != nil {
		return false
	}

	if decoded["role"] == "admin" {
		return true
	}
	return false
}

func main() {
	key, err := GenerateAesKey()
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

