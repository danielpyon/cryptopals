package main

import (
	"fmt"
	"encoding/hex"
)

func main() {
	padded := PadPkcs7([]byte("YELLOW SUBMARINE"), 20)
	fmt.Println(hex.EncodeToString(padded))

	ciphertext, _ := EncryptAesEcb([]byte("hello world!AAAA"), []byte("YELLOW SUBMARINE"))
	plaintext, _ := DecryptAesEcb(ciphertext, []byte("YELLOW SUBMARINE"))

	fmt.Println(BytesToString(plaintext))
}

 