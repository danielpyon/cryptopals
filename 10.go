package main

import (
	"fmt"
)

func main() {
	key := []byte("YELLOW SUBMARINE")
	ciphertext, err := EncryptAesCbc([]byte("AAAAAAAAAAAAAAAA"), key)

	if err != nil {
		fmt.Println("error: ", err)
		return
	}

	fmt.Println(ciphertext)

	plaintext, err := DecryptAesCbc(ciphertext, key)
	if err != nil {
		fmt.Println("error: ", err)
		return
	}
	
	fmt.Println(plaintext)
}