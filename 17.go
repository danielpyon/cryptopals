package main

import (
	"fmt"
	"io/ioutil"
	b64 "encoding/base64"
	"math/rand"
	"strings"
)

type PaddingOracle struct {
	key []byte
	plaintext []byte
}

func (o *PaddingOracle) Init() {
	var err error
	o.key, err = GenerateAesKey()
	if err != nil {
		panic("Could not generate key")
	}
}

func (o *PaddingOracle) Encrypt() []byte {
	data, err := ioutil.ReadFile("17.txt")
	if err != nil {
		panic("Could not read file")
	}

	split := strings.Split(string(data), "\n")
	var plaintexts [][]byte
	for _, s := range split {
		decoded, err := b64.StdEncoding.DecodeString(strings.TrimSpace(s))
		if err != nil {
			panic("Could not base64 decode a string")
		}
		plaintexts = append(plaintexts, decoded)
	}

	// pick a random plaintext
	idx := rand.Intn(len(plaintexts))
	plaintext := plaintexts[idx]

	padded := PadPkcs7(plaintext, 16)

	ciphertext, err := EncryptAesCbc(padded, o.key)
	if err != nil {
		panic("Could not encrypt plaintext")
	}

	return ciphertext
}

func (o *PaddingOracle) Decrypt(ciphertext []byte) bool {
	plaintext, err := DecryptAesCbc(ciphertext, o.key)
	if err != nil {
		panic("Could not decrypt message")
	}

	_, err = UnpadPkcs7(plaintext)
	return err == nil
}

func assert(condition bool, errorMessage string) {
	if !condition {
		panic("Failed assertion: " + errorMessage)
	}
}

func main() {
	fmt.Println("[+] === chall 17 ===")

	o := &PaddingOracle{}
	o.Init()
	ct := o.Encrypt()
	fmt.Printf("[+] length of ciphertext: %v\n", len(ct))

	// the full plaintext we are leaking
	// var fullPlaintext []byte

	assert(len(ct) % 16 == 0, "len(ct) % 16 != 0")
	for i := len(ct)-16; i > 0; i -= 16 {
		currBlock := ct[i:i+16] // block we are leaking
		prevBlock := ct[i-16:i] // block we are modifying

		assert(len(currBlock) % 16 == 0, "blocks should be 16 bytes")
		assert(len(prevBlock) % 16 == 0, "blocks should be 16 bytes")
		
		// array of currently leaked plaintext
		plaintext := make([]int, 16)
		FillSlice(plaintext, -1)

		// we will leak currBlock[leakByte]
		for leakByte := 15; leakByte >= 0; leakByte-- {
			desiredPadding := 15 - leakByte + 1

			// make a copy of prevBlock to modify
			prevBlockPadded := make([]byte, 16)
			assert(copy(prevBlockPadded, prevBlock) == 16, "copied wrong # of bytes")

			for j := 15; j >= 0 && plaintext[j] != -1; j-- {
				intermediateByte := byte(plaintext[j]) ^ prevBlock[j]
				prevBlockPadded[j] = byte(desiredPadding) ^ intermediateByte
			}

			// for each possible guess
			for x := 0; x < 256; x++ {
				guess := x ^ desiredPadding

				// create ct1
				ct1Buf := make([]byte, 16)
				copy(ct1Buf, prevBlockPadded)
				ct1Buf[leakByte] ^= byte(guess)
				ct1 := append(ct[:i-16], ct1Buf...)
				ct1 = append(ct1, currBlock...)
				assert(len(ct1) % 16 == 0, "len(ct1) is not a multiple of 16")

				// create ct2
				ct2Buf := make([]byte, 16)
				copy(ct2Buf, ct1Buf)
				if leakByte - 1 >= 0 {
					ct2Buf[leakByte - 1] = ^ct2Buf[leakByte - 1]
				}
				ct2 := append(ct[:i-16], ct2Buf...)
				ct2 = append(ct2, currBlock...)
				assert(len(ct2) % 16 == 0, "len(ct2) is not a multiple of 16")

				if o.Decrypt(ct1) && o.Decrypt(ct2) {
					plaintext[leakByte] = x
					fmt.Println( leakByte, x )
					break
				}
			}
		}

		// copy our current plaintext block to the full plaintext
	}
}