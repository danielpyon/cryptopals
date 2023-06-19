package set1

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"strings"
)

func Test8() {
	// get the input file
	data, err := ioutil.ReadFile("8.txt")
	if err != nil {
		panic("couldn't read file!")
	}

	split := strings.Split(string(data), "\n")
	result := make([][]byte, len(split))

	for i, s := range split {
		result[i], _ = hex.DecodeString(s)
	}

	contents := result

	for _, ct := range contents {
		// store a set of blocks
		// the value doesn't matter
		// the keys are strings because []byte keys aren't supported in go
		blocks := make(map[string]bool)

		// is this block encrypted with ecb mode?
		ecb := false

		if len(ct)%16 != 0 {
			continue
		}

		// check if the ciphertext contains any identical 16 byte blocks
		for j := 0; j < len(ct); j += 16 {
			currBlock := ct[j : j+16]
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

		if ecb {
			fmt.Println("ciphertext under ECB: ", hex.EncodeToString(ct))
			break
		}
	}
}
