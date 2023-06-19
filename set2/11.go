package set2

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"

	"github.com/danielpyon/cryptopals/lib"
)

// random int in [low, high]
func RandInt(low, high int64) int64 {
	diff := high - low + 1
	val, err := rand.Int(rand.Reader, big.NewInt(diff))
	if err != nil {
		panic("failed to generate rand int")
	}
	return val.Add(val, big.NewInt(low)).Int64()
}

// encrypt aes with CBC or ECB (1/2 probability)
// returns true if ECB mode was used, CBC otherwise
func AesOracle(data []byte) ([]byte, bool) {
	flipCoin := func() bool {
		val, err := rand.Int(rand.Reader, big.NewInt(2))
		if err != nil {
			panic("failed to flip coin")
		}
		return val.Int64() == 1
	}

	key, _ := lib.GenerateAesKey()

	// extra bytes appended to front / back of plaintext
	extraFront, extraBack := int(RandInt(5, 10)), int(RandInt(5, 10))

	plaintext := make([]byte, extraFront+len(data)+extraBack)
	_, err := rand.Read(plaintext[:extraFront])
	if err != nil {
		panic("failed to read random bytes")
	}
	_, err = rand.Read(plaintext[extraFront+len(data):])
	if err != nil {
		panic("failed to read random bytes")
	}

	// copy data to plaintext
	payload := plaintext[extraFront:]
	for i, x := range data {
		payload[i] = x
	}

	padded := lib.PadPkcs7(plaintext, 16)

	var ciphertext []byte
	var mode bool

	if flipCoin() {
		mode = true
		ciphertext, err = lib.EncryptAesEcb(padded, key)
	} else {
		mode = false
		ciphertext, err = lib.EncryptAesCbc(padded, key)
	}

	if err != nil {
		panic("couldn't encrypt")
	}

	return ciphertext, mode
}

// returns whether it guessed correctly
func DetectAes() bool {
	// do 32+20 bytes so even if there are 10 extra bytes added at the front,
	// we will have 2 blocks mapping to same ciphertext
	pt := make([]byte, 32+20)
	lib.FillSlice(pt, 0x41)
	ct, mode := AesOracle(pt)

	// this is the algorithm from problem 8 (detect ECB)
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
	}

	return ecb == mode
}
