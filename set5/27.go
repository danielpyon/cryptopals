package main

import (
	"crypto/aes"
	"errors"
	"fmt"
	"strings"
)

// AES-CBC with IV=key
func EncryptAesCbcIvEqKey(data, key []byte) ([]byte, error) {
	if len(data)%16 != 0 {
		return nil, errors.New("data length is not a multiple of 16")
	}

	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	encrypted := make([]byte, 16, len(data)+16)

	// generate the initialization vector
	copy(encrypted[:16], key)

	size := 16
	for start, end := 0, size; start < len(data); start, end = start+size, end+size {
		XorInPlace(data[start:end], encrypted[start:end])
		cipher.Encrypt(encrypted[start+size:end+size], data[start:end])
	}

	return encrypted[:cap(encrypted)], nil
}

type CbcOracle struct {
	key []byte
}

func (o *CbcOracle) Init() {
	var err error
	o.key, err = GenerateAesKey()

	if err != nil {
		panic("Could not generate AES key")
	}
}

func (o *CbcOracle) Encrypt(userData string) []byte {
	pre := "comment1=cooking%20MCs;userdata="
	post := ";comment2=%20like%20a%20pound%20of%20bacon"

	// sanitize user input
	userData = strings.ReplaceAll(userData, "=", "")
	userData = strings.ReplaceAll(userData, ";", "")

	plaintext := PadPkcs7([]byte(pre+userData+post), 16)

	ciphertext, err := EncryptAesCbcIvEqKey(plaintext, o.key)
	ciphertext = ciphertext[16:] // get rid of the IV
	if err != nil {
		panic("Could not encrypt plaintext")
	}

	return ciphertext
}

func (o *CbcOracle) Valid(ciphertext []byte) (bool, []byte) {
	ctWithIV := make([]byte, len(ciphertext)+len(o.key))
	copy(ctWithIV[16:], ciphertext)
	copy(ctWithIV[:16], o.key)

	plaintext, err := DecryptAesCbc(ctWithIV, o.key)
	if err != nil {
		panic("Could not decrypt ciphertext")
	}

	if err != nil {
		return false, plaintext
	}

	// check if any bytes are non-ASCII
	for _, x := range plaintext {
		if x >= 128 {
			return false, plaintext
		}
	}

	return true, plaintext
}

func main() {
	fmt.Println("[+] === chall 27 ===")

	o := &CbcOracle{}
	o.Init()
	ct := o.Encrypt("AAAAAAAAAAAAAAAA")
	fmt.Println("[+] original key:", o.key)

	// comment1=cooking %20MCs;userdata= AAAAAAAAAAAAAAAA
	fmt.Println("[+] length of ciphertext:", len(ct))

	// take the first block of the ciphertext (call it c1),
	// then create a new ciphertext c1||0^16||c1
	c1 := ct[:16]
	newCt := make([]byte, 16*3)
	copy(newCt[:16], c1)
	FillSlice(ct[16:32], 0)
	copy(newCt[32:48], c1)

	valid, pt := o.Valid(newCt)

	if !valid {
		key, _ := XOR(pt[:16], pt[32:48])
		fmt.Println("[+] recovered key:", key)

		// compare the recovered key and actual key
		for i := range o.key {
			if o.key[i] != key[i] {
				panic("[+] failed to recover key!")
			}
		}

		fmt.Println("[+] successfully recovered key!")
	}
}
