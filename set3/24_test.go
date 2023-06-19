package set3

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/danielpyon/cryptopals/lib"
	"github.com/danielpyon/cryptopals/set2"
)

func Test24(t *testing.T) {
	fmt.Println("[+] === chall 24 ===")

	numAs := 14
	numRand := int(set2.RandInt(10, 20))
	plaintext := make([]byte, numAs+numRand)

	// prefix the plaintext with some random bytes
	n, err := rand.Read(plaintext[:numRand])
	if err != nil || n != numRand {
		panic("could not generate random bytes!")
	}
	// fill the rest of the plaintext with A's
	lib.FillSlice(plaintext[numRand:], 0x41)
	fmt.Println(plaintext)

	// encrypt the plaintext with the mersenne twister PRNG
	seed := uint16(time.Now().Unix())
	ciphertext, err := lib.EncryptMT19937(plaintext, seed)
	if err != nil {
		panic("error encrypting plaintext")
	}

	// now we're gonna attack the cipher
	key := FindKey(ciphertext)
	fmt.Println("found key:", key)

	// make a token
	token, err := lib.EncryptMT19937([]byte("\x00\x00\x00\x00"), seed)
	if err != nil {
		panic("could not generate random bytes!")
	}
	fmt.Println(TokenFromMT19937(token))
}
