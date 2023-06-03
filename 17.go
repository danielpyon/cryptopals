package main

import (
	"fmt"
	"io/ioutil"
	b64 "encoding/base64"
	"math/rand"
	"strings"
	"encoding/hex"
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
		decoded, err := b64.StdEncoding.DecodeString(s)
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

func main() {
	fmt.Println("[+] === chall 17 ===")

	o := &PaddingOracle{}
	o.Init()

	ct := o.Encrypt()
	fmt.Println(hex.EncodeToString(ct))
}