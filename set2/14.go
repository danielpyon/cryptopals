package set2

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

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

	count := randInt(1, 32)
	o.prefix = make([]byte, count)
	_, _ = rand.Read(o.prefix)

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

// returns true if ECB mode was used
func DetectAesO(o Oracle) bool {
	pt := make([]byte, 32+20)
	lib.FillSlice(pt, 0x41)

	ct := o.Encrypt(pt)

	ecb := false
	blocks := make(map[string]bool)

	if len(ct)%16 == 0 {
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
		return ecb
	} else {
		return false
	}
}

func Test14(t *testing.T) {
	fmt.Println("[+] chall 14")

	o := AesOraclePersistentKeyRandomBytes{}
	o.Init()

	// find block size
	blockSize := FindBlockSize(&o)
	fmt.Printf("[+] block size: %v\n", blockSize)

	// detect ecb
	if !DetectAesO(&o) {
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
			panic("[+] couldn't leak! no entry found in table")
		}
		blockBytes, _ := hex.DecodeString(blockStr)
		leakedByte := blockBytes[len(blockBytes)-1]
		leak = append(leak, leakedByte)
		fmt.Println(lib.BytesToString(leak))
	}
}
