package main

import (
	"fmt"
)

func Edit(ciphertext []byte, key uint32, offset int, newtext []byte) {
	if offset < 0 || offset >= len(ciphertext) || offset+len(newtext) > len(ciphertext) {
		panic("invalid offset")
	}

	mt := &MT19937{}
	mt.Init(key)

	for i := 0; i < offset; i++ {
		_, err := mt.Rand()
		if err != nil {
			panic("failed to generate random number")
		}
	}

	for i := range newtext {
		val, err := mt.Rand()
		if err != nil {
			panic("failed to generate random number")
		}
		ciphertext[offset+i] = newtext[i] ^ byte(val)
	}
}

func main() {
	pt := []byte("Hello world")
	ct, _ := EncryptMT19937(pt, 1337)

	Edit(ct, 1337, 0, []byte("HI!"))

	newpt, _ := DecryptMT19937(ct, 1337)
	fmt.Println(BytesToString(newpt))
}
