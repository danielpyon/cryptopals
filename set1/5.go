package set1

import (
	"bytes"
	"encoding/hex"
	"fmt"

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

func Test5() {
	// should error handle but whatever
	test_case := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
	key := []byte("ICE")

	RepeatingKeyXOR(test_case, key)
	answer, _ := hex.DecodeString("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")

	if bytes.Equal(test_case, answer) {
		fmt.Println("test case passed!")
	} else {
		fmt.Println("test case failed!")
	}
}
