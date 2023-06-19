package set2

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/danielpyon/cryptopals/lib"
)

func Test(input []byte, testCaseNum int) {
	result, err := lib.UnpadPkcs7(input)
	if err != nil {
		fmt.Printf("Could not unpad message #%v\n", testCaseNum)
	} else {
		fmt.Printf("Successfully unpadded #%v\n", testCaseNum)
		fmt.Println(lib.BytesToString(result))
		fmt.Println(hex.EncodeToString(result))
	}
}

func Test15(t *testing.T) {
	fmt.Println("[+] === chall 15 ===")
	// should succeed
	Test([]byte("ICE ICE BABY\x04\x04\x04\x04"), 1)
	// should fail
	Test([]byte("ICE ICE BABY\x05\x05\x05\x05"), 2)
	// should fail
	Test([]byte("ICE ICE BABY\x01\x02\x03\x04"), 3)
}
