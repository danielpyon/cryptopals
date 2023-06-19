package set4

import (
	"fmt"
	"testing"
)

func Test26(t *testing.T) {
	fmt.Println("[+] === chall 26 ===")

	o := CtrOracle{}
	o.Init()
	ct := o.Encrypt(":admin<true:AAAA")

	// the ciphertext looks like this:
	// comment1=cooking %20MCs;userdata= :admin<true:AAAA ;comment2=%20lik e%20a%20pound%20 of%20bacon\x06\x06\x06\x06\x06\x06
	// note that instead of ";admin=true;", we have ":admin<true:"
	// this is because we will flip the corresponding bits

	// flip bits
	block := 2
	ct[block*16] ^= 1
	ct[block*16+6] ^= 1
	ct[block*16+11] ^= 1

	if !o.IsAdmin(ct) {
		t.Errorf("failed to get admin access!")
	}
}
