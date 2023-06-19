package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

type KeyStream struct {
	key          []byte
	nonce        uint64
	offset       uint64
	currBlockNum uint64
	currBlock    []byte

	cipher cipher.Block
}

func (ks *KeyStream) Init(key []byte, nonce uint64, offset uint64) {
	ks.key = key
	ks.nonce = nonce
	ks.offset = offset

	ks.currBlockNum = 0
	ks.currBlock = nil

	var err error
	ks.cipher, err = aes.NewCipher(key)
	if err != nil {
		panic("Could not create a cipher.")
	}
}

func (ks *KeyStream) NextByte() byte {
	// determine if we should get a new block
	blockNum := ks.offset / 16
	if ks.currBlockNum != blockNum || ks.currBlock == nil {
		ks.currBlockNum = blockNum
		ks.currBlock = make([]byte, 16)
		binary.LittleEndian.PutUint64(ks.currBlock[:8], ks.nonce)
		binary.LittleEndian.PutUint64(ks.currBlock[8:], ks.currBlockNum)
		ks.cipher.Encrypt(ks.currBlock, ks.currBlock)
	}

	ret := ks.currBlock[ks.offset%16]
	ks.offset++

	return ret
}

func Edit(ciphertext, key []byte, nonce, offset uint64, newText []byte) {
	if offset < 0 || int(offset) >= len(ciphertext) || int(offset)+len(newText) > len(ciphertext) {
		panic("Invalid offset.")
	}

	_, err := aes.NewCipher(key)
	if err != nil {
		panic("failed to create cipher")
	}

	ks := &KeyStream{}
	ks.Init(key, nonce, offset)

	for i := 0; i < len(newText); i++ {
		ciphertext[offset+uint64(i)] = ks.NextByte() ^ newText[i]
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
	newText := make([]byte, len(ct))
	FillSlice(newText, 0x00)

	// copy the ct
	keystream := make([]byte, len(ct))
	copy(keystream, ct)
	Edit(keystream, key, 0, 0, newText)

	// now, just xor the keystream with the data
	XorInPlace(ct, keystream)

	// now, ct should equal pt
	for i := range ct {
		if pt[i] != ct[i] {
			panic("Recovered plaintext is not equal to the original plaintext!")
		}
	}
	fmt.Println("Successfully recovered plaintext!")
}
