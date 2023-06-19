package set2

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/danielpyon/cryptopals/lib"
)

func Test14(t *testing.T) {
	fmt.Println("[+] chall 14")

	o := AesOraclePersistentKeyRandomBytes{}
	o.Init()

	// find block size
	blockSize := FindBlockSize(&o)
	fmt.Printf("[+] block size: %v\n", blockSize)

	// detect ecb
	if !DetectAesEcb(&o) {
		fmt.Println("[+] ecb mode not used")
		return
	}

	/// NEW STUFF FOR PROBLEM 14:
	// we want to find the number of random bytes that were prepended
	prefixSize := FindPrefixSize(&o, blockSize)
	bytesNeededForBlock := blockSize - (prefixSize % blockSize)
	fmt.Println("[+] prefix size:", prefixSize)
	fmt.Println("[+] bytes needed for the prefix to become a complete block:", bytesNeededForBlock)

	// first, compute number of blocks from just prefix bytes
	numPaddingBlocks := (prefixSize + bytesNeededForBlock) / blockSize
	numPaddingBlocks += 8

	startOfLeakedBlock := numPaddingBlocks * blockSize
	fmt.Println("[+] number of padding blocks:", numPaddingBlocks)
	fmt.Println("[+] the start of the leaked block (in bytes):", startOfLeakedBlock)

	var leak []byte
	for numPadding := startOfLeakedBlock - prefixSize + blockSize - 1; numPadding >= 0; numPadding-- {

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

			ct := hex.EncodeToString(o.Encrypt(plaintext)[startOfLeakedBlock : startOfLeakedBlock+blockSize])
			pt := hex.EncodeToString(plaintext[len(plaintext)-blockSize:])
			table[ct] = pt
		}

		blockStr, ok := table[hex.EncodeToString(leakedBlock)]
		if !ok {
			// this should fail but it's ok
			// panic("[+] couldn't leak! no entry found in table")
			return
		}
		blockBytes, _ := hex.DecodeString(blockStr)
		leakedByte := blockBytes[len(blockBytes)-1]
		leak = append(leak, leakedByte)
		fmt.Println(lib.BytesToString(leak))
	}
}
