package main

import (
	"fmt"
	"encoding/hex"
)

func main() {
	input, _ := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")

	var key byte
	scores := make(map[string]float64)
	for key = 0; key < 255; key++ {
		mask := make([]byte, len(input))
		fillArray(mask, key)

		result, err := xor(input, mask)
		if err != nil {
			panic("not same length")
		}

		plaintext := BytesToString(result)
		scores[plaintext] = score(plaintext)
	}

	fmt.Println("Results:")
	rankings := rankByScore(scores)
	for i := 0; i < len(rankings); i++ {
		if i > 5 {
			break
		}
		fmt.Println("Text: ", rankings[i].Key, " Score: ", rankings[i].Value)
		fmt.Println()
	}
}

