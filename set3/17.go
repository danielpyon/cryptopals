package set3

import (
	b64 "encoding/base64"
	"fmt"
	"io/ioutil"
	"math/rand"
	"strings"

	"github.com/danielpyon/cryptopals/lib"
)

type PaddingOracle struct {
	key       []byte
	plaintext []byte
}

func (o *PaddingOracle) Init() {
	var err error
	o.key, err = lib.GenerateAesKey()
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

	padded := lib.PadPkcs7(plaintext, 16)
	fmt.Println(padded)

	ciphertext, err := lib.EncryptAesCbc(padded, o.key)
	if err != nil {
		panic("Could not encrypt plaintext")
	}

	return ciphertext
}

func (o *PaddingOracle) Decrypt(ciphertext []byte) bool {
	if len(ciphertext) < 32 || len(ciphertext)%16 != 0 {
		return false
	}

	plaintext, err := lib.DecryptAesCbc(ciphertext, o.key)
	if err != nil {
		panic("Could not decrypt message")
	}

	_, err = lib.UnpadPkcs7(plaintext)
	return err == nil
}

func assert(condition bool, errorMessage string) {
	if !condition {
		panic("Failed assertion: " + errorMessage)
	}
}
