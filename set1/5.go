package set1

import (
	"github.com/danielpyon/cryptopals/lib"
)

func RepeatingKeyXOR(input, key []byte) {
	for i, v := range input {
		input[i] = v ^ key[i%len(key)]
	}
}

func BreakSingleXORCipher(ciphertext []byte) string {
	var key byte
	scores := make(map[string]float64)
	for key = 0; key < 255; key++ {
		mask := make([]byte, len(ciphertext))
		lib.FillSlice(mask, key)

		result, err := Xor(ciphertext, mask)
		if err != nil {
			panic("not same length")
		}

		plaintext := lib.BytesToString(result)
		scores[plaintext] = ScoreEnglish(plaintext)
	}

	rankings := RankByScore(scores)
	return rankings[0].Plaintext
}
