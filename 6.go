package main

import (
	"fmt"
	b64 "encoding/base64"
	"io/ioutil"
	"strings"
	"math"
)

func ParseInputFile() []byte {
	data, err := ioutil.ReadFile("6.txt")
	if err != nil {
		panic("failed to read file!")
	}

	split := strings.Split(string(data), "\n")
	var result string
	for _, s := range split {
		result += s
	}

	dec, err := b64.StdEncoding.DecodeString(result)
	if err != nil {
		panic("invalid base64!")
	}

	return dec
}

// transpose("helloworld", 3) = hlod, eor, lwl
func Transpose(xs []byte, bins int) [][]byte {
	transpose := make([][]byte, bins)
	for i, x := range xs {
		transpose[i % bins] = append(transpose[i % bins], x)
	}
	return transpose
}

func main() {
	fmt.Println("challenge 6")
	ciphertext := ParseInputFile()

	/// introduction
	// the distance between x and y is the same as the distance between
	// Enc(x, key) and Enc(y, key), assuming x and y are adjacent, key-sized
	// chunks.
	// the reason we take hamming distance is because in english, two key-sized
	// chunks should not differ very much (max dist is from A to Z).
	// whereas uniformly random bytes will differ quite a bit.

	/// example:
	// "hel|lo |wor|ld", "abc"
	// "2x9|j10|9sf|ai"
	// "2x|9j|10|9s|fa|i" <- this is gonna find the distance between two unrelated strings

	// step 1: guess the key size
	key_size_to_dist := make(map[int]int)
	for key_size := 2; key_size <= 40; key_size++ {
		// average different blocks
		// first, make sure we have enough room for the blocks
		if key_size * 3 <= len(ciphertext) {
			first := ciphertext[:key_size]
			second := ciphertext[key_size:key_size*2]
			third := ciphertext[key_size*2:key_size*3]
		
			dist1, err := HammingDistance(first, second)
			if err != nil {
				panic("differing lengths of input")
			}

			dist2, err := HammingDistance(second, third)
			if err != nil {
				panic("differing lengths of input")
			}

			dist3, err := HammingDistance(first, third)
			if err != nil {
				panic("differing lengths of input")
			}
			
			avg := (dist1+dist2+dist3)/3
			key_size_to_dist[key_size] = avg
		}
	}

	// take the lowest n distances
	key_size_guesses := make([]int, 6)
	for i := 0; i < len(key_size_guesses); i++ {
		// find minimum value entry in map and delete it
		min_dist := math.MaxInt
		min_key := 0
		for k, v := range key_size_to_dist {
			if v < min_dist {
				min_dist = v
				min_key = k
			}
		}

		// remove min key
		delete(key_size_to_dist, min_key)

		// add to key size guesses
		key_size_guesses[i] = min_key
	}

	fmt.Println("most likely key sizes: ", key_size_guesses)

	// step 2:
	// now, we just do the same thing as in earlier attacks but split the string into chunks
	for _, key_size := range key_size_guesses {
		for _, chunk := range Transpose(ciphertext, key_size) {
			plaintext := BreakSingleXORCipher(chunk)
			fmt.Println(plaintext)
		}
	}

	// step 3:

}
