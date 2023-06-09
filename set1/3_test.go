package set1

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/danielpyon/cryptopals/lib"
)

func Test3(t *testing.T) {
	input, _ := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")

	var key byte
	scores := make(map[string]float64)
	for key = 0; key < 255; key++ {
		mask := make([]byte, len(input))
		lib.FillSlice(mask, key)

		result, err := Xor(input, mask)
		if err != nil {
			panic("not same length")
		}

		plaintext := lib.BytesToString(result)
		scores[plaintext] = ScoreEnglish(plaintext)
	}

	fmt.Println("Results:")
	rankings := RankByScore(scores)
	for i := 0; i < len(rankings); i++ {
		if i > 5 {
			break
		}
		fmt.Println("Text: ", rankings[i].Plaintext, " Score: ", rankings[i].Score)
		fmt.Println()
	}
}
