package main

import (
	"fmt"
	"encoding/hex"
	b64 "encoding/base64"
)

// Converts a hex string to base64
func hex_to_base64(input string) string {
	// First, convert the input string into byte[]
	bytes, err := hex.DecodeString(input)
	if err != nil {
		panic(err)
	}

	// Then, convert the bytes into base64
	encoded := b64.StdEncoding.EncodeToString(bytes)
	return encoded
}

func main() {
	encoded := hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	correct_answer := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	
	if (encoded == correct_answer) {
		fmt.Println("Correct!")
	} else {
		fmt.Println("Incorrect!")
	}
}

