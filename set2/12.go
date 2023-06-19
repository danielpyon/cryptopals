package set2

import (
	"encoding/hex"

	"github.com/danielpyon/cryptopals/lib"
	"github.com/danielpyon/cryptopals/set1"
)

type Oracle interface {
	Init()
	Encrypt([]byte) []byte
}

// oracle with persistent key
type AesOraclePersistentKey struct {
	key       []byte
	extraData []byte // the data we are trying to leak
}

func (o *AesOraclePersistentKey) Init() {
	o.key, _ = lib.GenerateAesKey()
	o.extraData, _ = set1.ReadBase64EncodedFile("12.txt")
}

func (o *AesOraclePersistentKey) Encrypt(data []byte) []byte {
	plaintext := lib.PadPkcs7(append(data, o.extraData...), 16)
	ciphertext, _ := lib.EncryptAesEcb(plaintext, o.key)
	return ciphertext
}

func FindBlockSize(o Oracle) int {
	pt := []byte("A")
	initialLen := len(o.Encrypt(pt))
	currLen := initialLen
	for currLen == initialLen {
		pt = append(pt, 0x41)
		currLen = len(o.Encrypt(pt))
	}
	return currLen - initialLen
}

// returns true if ECB mode was used
func DetectAesEcb(o Oracle) bool {
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
