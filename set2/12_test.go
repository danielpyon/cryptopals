package set2

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/danielpyon/cryptopals/lib"
)

func Test12(t *testing.T) {
	// This does the byte-by-byte ECB attack

	fmt.Println("[+] chall 12")

	o := AesOraclePersistentKey{}
	o.Init()

	// find block size
	blockSize := FindBlockSize(&o)
	fmt.Printf("[+] block size: %v\n", blockSize)

	// detect ecb
	if !DetectAesEcb(&o) {
		t.Errorf("ecb mode not used")
		return
	}

	// create a bunch of padding before the leak bytes
	// [block 1 of padding] [block 2 of padding] [block 3 of padding][leak byte]
	numPaddingBlocks := 8 // # of blocks of padding before the block containing leaked byte
	startOfLeakedBlock := numPaddingBlocks * blockSize

	// NOTE: this should panic but leak the entire plaintext
	var leak []byte
	for numPadding := startOfLeakedBlock + blockSize - 1; numPadding >= 0; numPadding-- {
		// create numPadding A's, then get the block containing the leaked byte
		padding := make([]byte, numPadding)
		lib.FillSlice(padding, 0x41)
		leakedBlock := o.Encrypt(padding)[startOfLeakedBlock : startOfLeakedBlock+blockSize]

		// table maps from ciphertext to plaintext
		table := make(map[string]string)

		// use all possible last bytes to construct the table
		for x := 0; x <= 0xff; x++ {
			// append the current leak to our padding
			plaintext := append(padding, leak...)
			plaintext = append(plaintext, byte(x))
			plaintext = plaintext[startOfLeakedBlock : startOfLeakedBlock+blockSize]

			ct := hex.EncodeToString(o.Encrypt(plaintext)[:blockSize])
			pt := hex.EncodeToString(plaintext)
			table[ct] = pt
		}

		blockStr, ok := table[hex.EncodeToString(leakedBlock)]
		if !ok {
			// this should fail at some point but it's ok
			// t.Errorf("couldn't leak! no entry found in table")
			return
		}
		blockBytes, _ := hex.DecodeString(blockStr)
		leakedByte := blockBytes[len(blockBytes)-1]
		leak = append(leak, leakedByte)
		fmt.Println(lib.BytesToString(leak))
	}
}
