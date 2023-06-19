package main

import (
	"fmt"
	"encoding/hex"
)

// oracle with persistent key
type AesOracle struct {
	key []byte
	extraData []byte // the data we are trying to leak
}

func (o *AesOracle) Init() {
	o.key, _ = GenerateAesKey()
	o.extraData, _ = ReadBase64EncodedFile("12.txt")
}

func (o *AesOracle) Encrypt(data []byte) []byte {
	plaintext := PadPkcs7(append(data, o.extraData...), 16)
	ciphertext, _ := EncryptAesEcb(plaintext, o.key)
	return ciphertext
}

func FindBlockSize(o *AesOracle) int {
	pt := []byte("A")
	initialLen := len(o.Encrypt(pt))
	currLen := initialLen
	for ; currLen == initialLen; {
		pt = append(pt, 0x41)
		currLen = len(o.Encrypt(pt))
	}
	return currLen - initialLen
}

// returns true if ECB mode was used
func DetectAes(o *AesOracle) bool {
	pt := make([]byte, 32+20)
	FillSlice(pt, 0x41)

	ct := o.Encrypt(pt)

	ecb := false
	blocks := make(map[string]bool)

	if len(ct) % 16 == 0 {
		// check if the ciphertext contains any identical 16 byte blocks
		for j := 0; j < len(ct); j+=16 {
			currBlock := ct[j:j+16]
			currBlockStr := hex.EncodeToString(currBlock)

			_, ok := blocks[currBlockStr]
			if ok {
				// the block has been seen before, so this is probably ECB mode
				ecb = true
				break
			} else {
				blocks[currBlockStr] = true
			}
		}
		return ecb
	} else {
		return false
	}
}

func main() {
	fmt.Println("[+] chall 12")

	o := AesOracle{}
	o.Init()

	// find block size
	blockSize := FindBlockSize(&o)
	fmt.Printf("[+] block size: %v\n", blockSize)

	// detect ecb
	if !DetectAes(&o) {
		fmt.Println("[+] ecb mode not used")
		return
	}

	// create a bunch of padding before the leak bytes
	// [block 1 of padding] [block 2 of padding] [block 3 of padding][leak byte]
	numPaddingBlocks := 8 // # of blocks of padding before the block containing leaked byte
	startOfLeakedBlock := numPaddingBlocks * blockSize
	
	var leak []byte
	for numPadding := startOfLeakedBlock + blockSize - 1; numPadding >= 0; numPadding-- {
		// create numPadding A's, then get the block containing the leaked byte
		padding := make([]byte, numPadding)
		FillSlice(padding, 0x41)
		leakedBlock := o.Encrypt(padding)[startOfLeakedBlock:startOfLeakedBlock+blockSize]

		// table maps from ciphertext to plaintext
		table := make(map[string]string)

		// use all possible last bytes to construct the table
		for x := 0; x <= 0xff; x++ {
			// append the current leak to our padding
			plaintext := append(padding, leak...)
			plaintext = append(plaintext, byte(x))
			plaintext = plaintext[startOfLeakedBlock:startOfLeakedBlock+blockSize]

			ct := hex.EncodeToString(o.Encrypt(plaintext)[:blockSize])
			pt := hex.EncodeToString(plaintext)
			table[ct] = pt
		}

		blockStr, ok := table[hex.EncodeToString(leakedBlock)]
		if !ok {
			panic("[+] couldn't leak! no entry found in table")
		}
		blockBytes, _ := hex.DecodeString(blockStr)
		leakedByte := blockBytes[len(blockBytes) - 1]
		leak = append(leak, leakedByte)
		fmt.Println(BytesToString(leak))
	}
}