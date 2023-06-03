package main

import (
	"fmt"
	"encoding/hex"
	"crypto/rand"
	"math/big"
)

// oracle with persistent key
type AesOracle struct {
	key []byte
	extraData []byte // the data we are trying to leak
	prefix []byte
}

func (o *AesOracle) Init() {
	o.key, _ = GenerateAesKey()
	o.extraData, _ = ReadBase64EncodedFile("12.txt")

	// generate some random bytes to prepend
	randInt := func(low, high int64) int64 {
		diff := high - low + 1
		val, err := rand.Int(rand.Reader, big.NewInt(diff))
		if err != nil {
			panic("failed to generate rand int")
		}
		return val.Add(val, big.NewInt(low)).Int64()
	}

	count := randInt(1, 32)
	o.prefix = make([]byte, count)
	_, _ = rand.Read(o.prefix)

	fmt.Printf("added %v bytes.\n", count)
	fmt.Println(hex.EncodeToString(o.prefix))
}

func (o *AesOracle) Encrypt(data []byte) []byte {
	// append extra data to end (the thing we're trying to leak)
	payload := append(data, o.extraData...)
	// prepend random bytes to the front
	payload = append(o.prefix, payload...)

	plaintext := PadPkcs7(payload, 16)
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

// find the number of blocks that were prepended (the prefix)
func FindPrefixSize(o *AesOracle, blockSize int) int {
	// increase the number of A's until there are two identical blocks.
	// then, you'll have something like:
	// ciphertext = prefix + A...A | AAA...A | AAA...A | secret
	
	// so just return the number of bytes before the first AAA...A block
	// MINUS the number of A's required mod block size

	padding := []byte("A")
	for {
		ct := o.Encrypt(padding)
		
		// find identical blocks
		identicalBlocksFound := false
		var identicalBlock string

		blocks := make(map[string]bool)
		for i := 0; i < len(ct); i += blockSize {
			block := hex.EncodeToString(ct[i:i+blockSize])
			if _, ok := blocks[block]; ok {
				identicalBlocksFound = true
				identicalBlock = block
				break
			}
			blocks[block] = true
		}

		if identicalBlocksFound {
			// compute the prefix size
			prefixSize := -1
			for i := 0; i < len(ct); i += blockSize {
				if hex.EncodeToString(ct[i:i+blockSize]) == identicalBlock {
					prefixSize = i
					break
				}
			}
			
			if prefixSize == -1 {
				return -1
			}

			prefixSize -= len(padding) % blockSize
			return prefixSize
		}

		padding = append(padding, byte(0x41))
	}
}

func main() {
	fmt.Println("[+] chall 14")

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

	
	/// NEW STUFF FOR PROBLEM 14:
	// we want to find the number of random bytes that were prepended
	prefixSize := FindPrefixSize(&o, blockSize)
	fmt.Println("prefix size: ", prefixSize)
	return

	// create a bunch of padding before the leak bytes
	// [block 1 of padding] [block 2 of padding] [block 3 of padding][leak byte]
	numPaddingBlocks := 8 // # of blocks of padding before the block containing leaked byte
	startOfLeakedBlock := numPaddingBlocks * blockSize
	
	var leak []byte
	for numPadding := blockSize * numPaddingBlocks + blockSize - 1; numPadding >= 0; numPadding-- {
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