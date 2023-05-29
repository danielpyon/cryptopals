package main

import (
	"fmt"
	"bytes"
	"encoding/hex"
)

func main() {
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
