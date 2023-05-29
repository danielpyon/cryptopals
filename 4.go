package main

import (
	"fmt"
	"encoding/hex"
	"io/ioutil"
	"strings"
)

func ParseInputFile() [][]byte {
	data, err := ioutil.ReadFile("4.txt")
	if err != nil {
		panic("failed to read file!")
	}
	split := strings.Split(string(data), "\n")
	ret := make([][]byte, len(split))
	for i, s := range split {
		bytes, err := hex.DecodeString(s)
		if err != nil {
			panic("couldn't decode string!")
		}
		ret[i] = bytes
	}
	return ret
}

func main() {
	// array of ciphertexts
	cts := ParseInputFile()
	
	// map from string to its score
	scores := make(map[string]float64)
	
	// populate scores map
	for _, ct := range cts {
		// for each ciphertext, compute scores with all possible keys
		var key byte
		for key = 0; key < 255; key++ {
			mask := make([]byte, len(ct))
			FillArray(mask, key)
	
			result, err := XOR(ct, mask)
			if err != nil {
				panic("not same length")
			}
	
			plaintext := BytesToString(result)
			scores[plaintext] = ScoreEnglish(plaintext)
		}
	}

	ranked := RankByScore(scores)
	i := 0
	for _, pr := range ranked {
		if i >= 10 {
			break
		}

		if pr.Value == 0.0 {
			continue
		} else {
			i++
		}

		fmt.Println("String: ", pr.Key, " Value: ", pr.Value)
	}
	fmt.Println()
}
