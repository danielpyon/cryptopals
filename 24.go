package main

import (
	"fmt"
	"crypto/rand"
	"time"
)

func SliceEq(a, b []byte) bool {
    if len(a) != len(b) {
        return false
    }
    for i := range a {
        if a[i] != b[i] {
            return false
        }
    }
    return true
}

func FindKey(ciphertext []byte) uint16 {
	desiredPlaintext := make([]byte, 14)
	FillSlice(desiredPlaintext, 0x41)
	
	i := uint16(0)
	found := false
	for ; i < 0xffff; i++ {
		plaintext, err := DecryptMT19937(ciphertext, i)
		if err != nil {
			panic("failed to decrypt")
		}

		if SliceEq(plaintext[len(plaintext)-14:], desiredPlaintext) {
			found = true
			break
		}
	}

	if !found {
		panic("couldn't find key!")
	}

	return i
}

func main() {
	fmt.Println("[+] === chall 24 ===")

	numAs := 14
	numRand := int(randInt(10, 20))
	plaintext := make([]byte, numAs + numRand)

	// prefix the plaintext with some random bytes
	n, err := rand.Read(plaintext[:numRand])
	if err != nil || n != numRand {
		panic("could not generate random bytes!")
	}
	// fill the rest of the plaintext with A's
	FillSlice(plaintext[numRand:], 0x41)
	fmt.Println(plaintext)

	// encrypt the plaintext with the mersenne twister PRNG
	seed := uint16(time.Now().Unix())
	ciphertext, err := EncryptMT19937(plaintext, seed)
	if err != nil {
		panic("error encrypting plaintext")
	}

	// now we're gonna attack the cipher
	key := FindKey(ciphertext)
	fmt.Println("found key:", key)
}
