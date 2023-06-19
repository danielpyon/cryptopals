package set2

import (
	"fmt"
	"testing"

	"github.com/danielpyon/cryptopals/lib"
)

// returns true if the input could be unpadded successfully, false otherwise
func test15Helper(input []byte) bool {
	_, err := lib.UnpadPkcs7(input)
	return err == nil
}

func Test15(t *testing.T) {
	fmt.Println("[+] === chall 15 ===")
	// should succeed
	if !test15Helper([]byte("ICE ICE BABY\x04\x04\x04\x04")) {
		t.Errorf("case 1 failed")
	}

	// should fail
	if test15Helper([]byte("ICE ICE BABY\x05\x05\x05\x05")) {
		t.Errorf("case 2 failed")
	}

	// should fail
	if test15Helper([]byte("ICE ICE BABY\x01\x02\x03\x04")) {
		t.Errorf("case 3 failed")
	}
}
