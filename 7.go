package main

import (
	"fmt"
)



func main() {
	ciphertext, err := ReadBase64EncodedFile("7.txt")
	if err != nil {
		panic("could not read file!")
	}

	key := []byte("YELLOW SUBMARINE")
	plaintext := DecryptAesEcb(ciphertext, key)
	fmt.Println(BytesToString(plaintext))
}