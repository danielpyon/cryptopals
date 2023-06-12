package main

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

func Edit(ciphertext, key []byte, nonce uint64, offset int, newtext []byte) {
	if offset < 0 || offset >= len(ciphertext) || offset+len(newtext) > len(ciphertext) {
		panic("invalid offset")
	}

	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic("failed to create cipher")
	}

	i := offset
	total := 0
	for {
		startOfBlock := i
		if i%16 != 0 {
			startOfBlock = i - i%16
			total += 16 - i%16
		} else {
			total += 16
		}

		if total+16 < len(newtext) {
			i = startOfBlock + 16
		} else {

		}
	}

	// First, get the keystream bytes
	keystream := make([]byte, len(newtext))
	j := 0
	for i := offset - (offset % 16); i < offset+len(newtext); i += 16 {
		blockNum := uint64(i / 16)
		ctr := make([]byte, 16)
		binary.LittleEndian.PutUint64(ctr[:8], nonce)
		binary.LittleEndian.PutUint64(ctr[8:], blockNum)

		tmp := make([]byte, 16)
		cipher.Encrypt(tmp, ctr)
		copy(keystream[i:i+16], tmp)
		j += 16
	}
}

func main() {
	// read 25.txt to get plaintext
	pt, err := ReadBase64EncodedFile("25.txt")
	fmt.Println(BytesToString(pt))
	if err != nil {
		panic("could not read file")
	}

	// encrypt plaintext with random key
	key := make([]byte, 16)
	n, err := rand.Read(key)
	if n != 16 || err != nil {
		panic("could not generate random key")
	}

	ct, err := EncryptAesCtr(pt, key, 0)
	if err != nil {
		panic("could not encrypt")
	}

	// edit the CT to all zeros to get the bytes from the keystream
	newtext := make([]byte, len(ct))
	FillSlice(newtext, 0x00)

	// copy the ct
	keystream := make([]byte, len(ct))
	copy(keystream, ct)
	Edit(keystream, key, 0, newtext)

	// now, just xor the keystream with the data
	XorInPlace(ct, keystream)
}
