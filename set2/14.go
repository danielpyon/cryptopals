package set2

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/danielpyon/cryptopals/lib"
	"github.com/danielpyon/cryptopals/set1"
)

// oracle with persistent key
type AesOraclePersistentKeyRandomBytes struct {
	key       []byte
	extraData []byte // the data we are trying to leak
	prefix    []byte
}

func (o *AesOraclePersistentKeyRandomBytes) Init() {
	o.key, _ = lib.GenerateAesKey()
	o.extraData, _ = set1.ReadBase64EncodedFile("12.txt")

	count := RandInt(1, 32)
	o.prefix = make([]byte, count)
	rand.Read(o.prefix)

	fmt.Printf("[+] added %v bytes.\n", count)
	fmt.Println("[+] the random bytes:", hex.EncodeToString(o.prefix))
}

func (o *AesOraclePersistentKeyRandomBytes) Encrypt(data []byte) []byte {
	// append extra data to end (the thing we're trying to leak)
	payload := append(data, o.extraData...)
	// prepend random bytes to the front
	payload = append(o.prefix, payload...)

	plaintext := lib.PadPkcs7(payload, 16)
	ciphertext, _ := lib.EncryptAesEcb(plaintext, o.key)
	return ciphertext
}

// find the number of blocks that were prepended (the prefix)
func FindPrefixSize(o Oracle, blockSize int) int {
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
			block := hex.EncodeToString(ct[i : i+blockSize])
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
