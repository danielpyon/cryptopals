package main

import (
	"fmt"
)

func main() {
	encoded := hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	correct_answer := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	
	if (encoded == correct_answer) {
		fmt.Println("Correct!")
	} else {
		fmt.Println("Incorrect!")
	}
}

