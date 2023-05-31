package main

import (
	"fmt"
	"encoding/hex"
)

func main() {
	fmt.Println("chall 11")
	ciphertext := AesOracle([]byte("hello world"))
	fmt.Println(hex.EncodeToString(ciphertext))

}