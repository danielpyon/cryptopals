package main

import (
	"fmt"
)

func main() {
	key := []byte("YELLOW SUBMARINE")

	/*
	ciphertext, err := EncryptAesCbc([]byte("AAAAAAAAAAAAAAAA"), key)

	if err != nil {
		fmt.Println("error: ", err)
		return
	}

	fmt.Println(ciphertext)
	*/

	// given test case
	ciphertext, err := ReadBase64EncodedFile("10.txt")
	plaintext, err := DecryptAesCbc(ciphertext, key)
	if err != nil {
		fmt.Println("error: ", err)
		return
	}
	
	plaintextString := BytesToString(plaintext)
	fmt.Println(plaintextString)
}