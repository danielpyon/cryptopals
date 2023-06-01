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
	fmt.Println("chall 12")

	o := AesOracle{}
	o.Init()

	// find block size
	blockSize := FindBlockSize(&o)
	fmt.Printf("block size: %v\n", blockSize)

	// detect ecb
	if !DetectAes(&o) {
		fmt.Println("ecb mode not used")
		return
	}

	input := make([]byte, blockSize - 1)
	FillSlice(input, 0x41)
	ciphertext := hex.EncodeToString(o.Encrypt(input)[:blockSize])

	// table maps ciphertext -> plaintext that produced the ciphertext
	table := make(map[string]string)
	for x := 0; x <= 0xff; x++ {
		input := make([]byte, blockSize)
		FillSlice(input, 0x41)
		input[len(input)-1] = byte(x)

		ct := hex.EncodeToString(o.Encrypt(input)[:blockSize])
		pt := hex.EncodeToString(input)
		table[ct] = pt
	}

	fmt.Println(ciphertext)
	plaintext, ok := table[ciphertext]
	fmt.Println(ok)
	fmt.Println(plaintext)


}