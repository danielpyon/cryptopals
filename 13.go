package main

import (
	"fmt"
	"strings"
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


func main() {
	key, err := GenerateAesKey()
	if err != nil {
		panic(err)
	}

	fmt.Println(BytesToString(DecryptProfile(EncryptProfile("foo@bar.com", key), key)))
}