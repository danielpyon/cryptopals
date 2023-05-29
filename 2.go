package main

import (
	"fmt"
	"bytes"
	"encoding/hex"
)

func main() {
	a, _ := hex.DecodeString("1c0111001f010100061a024b53535009181c")
	b, _ := hex.DecodeString("686974207468652062756c6c277320657965")

	var c []byte
	var err error
	if c, err = xor(a, b); err != nil {
		fmt.Println("Failed: ", err)
		return
	}

	answer, _ := hex.DecodeString("746865206b696420646f6e277420706c6179")
	if bytes.Equal(c, answer) {
		fmt.Println("Correct!")
	} else {
		fmt.Println("Incorrect!")
	}
}

