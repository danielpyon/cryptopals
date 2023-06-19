package set1

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/danielpyon/cryptopals/lib"
)

func HammingDistance(a, b []byte) (int, error) {
	if len(a) != len(b) {
		return 0, errors.New("differing lengths of bytes")
	}

	hamming_dist := 0
	length := len(a)
	for i := 0; i < length; i++ {
		xor := a[i] ^ b[i]
		// count the number of ones in xor
		// because this is the number of differing bit positions
		dist := 0
		for j := 0; j < 8; j++ {
			if xor&1 == 1 {
				dist++
			}
			xor >>= 1
		}

		hamming_dist += dist
	}

	return hamming_dist, nil
}

func Test4() {
	// get the array of ciphertexts
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
	cts := ret

	// map from string to its score
	scores := make(map[string]float64)

	// populate scores map
	for _, ct := range cts {
		// for each ciphertext, compute scores with all possible keys
		var key byte
		for key = 0; key < 255; key++ {
			mask := make([]byte, len(ct))
			lib.FillSlice(mask, key)

			result, err := Xor(ct, mask)
			if err != nil {
				panic("not same length")
			}

			plaintext := lib.BytesToString(result)
			scores[plaintext] = ScoreEnglish(plaintext)
		}
	}

	ranked := RankByScore(scores)
	i := 0
	for _, pr := range ranked {
		if i >= 10 {
			break
		}

		if pr.Score == 0.0 {
			continue
		} else {
			i++
		}

		fmt.Println("String: ", pr.Plaintext, " Value: ", pr.Score)
	}
	fmt.Println()
}
