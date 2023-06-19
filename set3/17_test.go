package set3

import (
	"fmt"
	"os"
	"testing"

	"github.com/danielpyon/cryptopals/lib"
)

func Test17(t *testing.T) {
	// TODO: remove this when done with padding oracle
	return

	fmt.Println("[+] === chall 17 ===")

	// stall for debugging purposes
	o := &PaddingOracle{}
	o.Init()
	ct := o.Encrypt()
	fmt.Printf("[+] length of ciphertext: %v\n", len(ct))

	// the full plaintext we are leaking
	var fullPlaintext []int

	assert(len(ct)%16 == 0, "len(ct) % 16 != 0")
	for i := len(ct) - 16; i > 0; i -= 16 {
		currBlock := ct[i : i+16] // block we are leaking
		prevBlock := ct[i-16 : i] // block we are modifying

		assert(len(currBlock)%16 == 0, "blocks should be 16 bytes")
		assert(len(prevBlock)%16 == 0, "blocks should be 16 bytes")

		// array of currently leaked plaintext
		plaintext := make([]int, 16)
		lib.FillSlice(plaintext, -1)

		// we will leak currBlock[leakByte]
		for leakByte := 15; leakByte >= 0; leakByte-- {
			desiredPadding := 15 - leakByte + 1

			// make a copy of prevBlock to modify
			prevBlockPadded := make([]byte, 16)
			assert(copy(prevBlockPadded, prevBlock) == 16, "copied wrong # of bytes")

			// fmt.Printf("plaintext = %v\n", plaintext)
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
				assert(len(ct1)%16 == 0, "len(ct1) is not a multiple of 16")

				// create ct2
				ct2Buf := make([]byte, 16)
				copy(ct2Buf, ct1Buf)
				if leakByte-1 >= 0 {
					ct2Buf[leakByte-1] = ^ct2Buf[leakByte-1]
				}
				ct2 := append(ct[:i-16], ct2Buf...)
				ct2 = append(ct2, currBlock...)
				assert(len(ct2)%16 == 0, "len(ct2) is not a multiple of 16")

				if o.Decrypt(ct1) && o.Decrypt(ct2) {
					plaintext[leakByte] = x
					fmt.Printf("plaintext[%v] = %v\n", leakByte, x)
					os.Exit(0)
					break
				}
			}
		}

		// copy our current plaintext block to the full plaintext
		fullPlaintext = append(fullPlaintext, plaintext...)
	}

	fmt.Println(fullPlaintext)
}
