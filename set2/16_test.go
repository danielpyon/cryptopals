package set2

import (
	"fmt"
	"testing"
)

func Test16(t *testing.T) {
	fmt.Println("[+] === chall 16 ===")

	o := CbcOracle{}
	o.Init()
	ct := o.Encrypt("AAAAAAAAAAAAAAAA:admin<true:AAAA")

	// the ciphertext looks like this:
	// init-vector comment1=cooking %20MCs;userdata= AAAAAAAAAAAAAAAA :admin<true:AAAA ;comment2=%20lik e%20a%20pound%20 of%20bacon\x06\x06\x06\x06\x06\x06
	// note that instead of ";admin=true;", we have ":admin<true:"
	// this is because we will flip the corresponding bits

	// flip bits
	block := 3 // we must modify the PREVIOUS block
	ct[block*16] ^= 1
	ct[block*16+6] ^= 1
	ct[block*16+11] ^= 1

	if !o.IsAdmin(ct) {
		t.Errorf("failed to get admin access!")
	}
}
