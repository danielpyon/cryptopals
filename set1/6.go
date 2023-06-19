package set1

import (
	"math"

	"github.com/danielpyon/cryptopals/lib"
)

func BreakSingleXORCipherWithKey(ciphertext []byte) (string, byte) {
	var key byte
	scores := make(map[string]float64)
	plaintext_to_key := make(map[string]byte)
	for key = 0; key < 255; key++ {
		mask := make([]byte, len(ciphertext))
		lib.FillSlice(mask, key)

		result, err := Xor(ciphertext, mask)
		if err != nil {
			panic("not same length")
		}

		plaintext := lib.BytesToString(result)

		scores[plaintext] = ScoreEnglish(plaintext)
		plaintext_to_key[plaintext] = key
	}

	rankings := RankByScore(scores)
	pt := rankings[0].Plaintext
	return pt, plaintext_to_key[pt]
}

// transpose("helloworld", 3) = hlod, eor, lwl
func Transpose(xs []byte, bins int) [][]byte {
	transpose := make([][]byte, bins)
	for i, x := range xs {
		transpose[i%bins] = append(transpose[i%bins], x)
	}
	return transpose
}

// InvTranspose([[a b c] [d e f] [g h i]]) = adgbehcfi
func InvTranspose(transpose []string) string {
	max := math.MinInt
	for _, str := range transpose {
		if len(str) > max {
			max = len(str)
		}
	}

	// idea: advance the "head" of each bin
	// current "head" of bin
	var ret string
	var i int
	for i = 0; i < max; i++ {
		// get the head of each bin
		var tmp string

		for j := 0; j < len(transpose); j++ {
			if i < len(transpose[j]) {
				tmp += string(transpose[j][i])
			} else {
				break
			}
		}
		ret += tmp
	}
	return ret
}
