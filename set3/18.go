package main

import (
	"fmt"
	b64 "encoding/base64"
)

func main() {
	ciphertext, _ := b64.StdEncoding.DecodeString("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	plaintext, err := DecryptAesCtr(ciphertext, []byte("YELLOW SUBMARINE"), 0)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(BytesToString(plaintext))
}