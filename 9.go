package main

import (
	"fmt"
	"encoding/hex"
)

func main() {
	padded := PadPkcs7([]byte("YELLOW SUBMARINE"), 20)
	fmt.Println(hex.EncodeToString(padded))

	ciphertext := EncryptAesEcb([]byte("hello world!AAAA"), []byte("YELLOW SUBMARINE"))
	plaintext := DecryptAesEcb(ciphertext, []byte("YELLOW SUBMARINE"))
	fmt.Println(BytesToString(plaintext))
}

 