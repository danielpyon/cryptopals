package set4

import (
	"fmt"
	"testing"

	"github.com/danielpyon/cryptopals/lib"
	"github.com/danielpyon/cryptopals/set1"
)

func Test27(t *testing.T) {
	fmt.Println("[+] === chall 27 ===")

	o := &CbcOracle{}
	o.Init()
	ct := o.Encrypt("AAAAAAAAAAAAAAAA")
	fmt.Println("[+] original key:", o.key)

	// comment1=cooking %20MCs;userdata= AAAAAAAAAAAAAAAA
	fmt.Println("[+] length of ciphertext:", len(ct))

	// take the first block of the ciphertext (call it c1),
	// then create a new ciphertext c1||0^16||c1
	c1 := ct[:16]
	newCt := make([]byte, 16*3)
	copy(newCt[:16], c1)
	lib.FillSlice(ct[16:32], 0)
	copy(newCt[32:48], c1)

	valid, pt := o.Valid(newCt)

	if !valid {
		key, _ := set1.Xor(pt[:16], pt[32:48])
		fmt.Println("[+] recovered key:", key)

		// compare the recovered key and actual key
		for i := range o.key {
			if o.key[i] != key[i] {
				t.Errorf("failed to recover key!")
			}
		}

		fmt.Println("[+] successfully recovered key!")
	}
}
