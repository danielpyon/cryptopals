package set4

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/danielpyon/cryptopals/lib"
	"github.com/danielpyon/cryptopals/set1"
)

func Test25(t *testing.T) {
	// read 25.txt to get plaintext
	pt, err := set1.ReadBase64EncodedFile("25.txt")
	fmt.Println(lib.BytesToString(pt))
	if err != nil {
		panic("could not read file")
	}

	// encrypt plaintext with random key
	key := make([]byte, 16)
	n, err := rand.Read(key)
	if n != 16 || err != nil {
		panic("could not generate random key")
	}

	ct, err := lib.EncryptAesCtr(pt, key, 0)
	if err != nil {
		panic("could not encrypt")
	}

	// edit the CT to all zeros to get the bytes from the keystream
	newText := make([]byte, len(ct))
	lib.FillSlice(newText, 0x00)

	// copy the ct
	keystream := make([]byte, len(ct))
	copy(keystream, ct)
	Edit(keystream, key, 0, 0, newText)

	// now, just xor the keystream with the data
	lib.XorInPlace(ct, keystream)

	// now, ct should equal pt
	for i := range ct {
		if pt[i] != ct[i] {
			t.Errorf("Recovered plaintext is not equal to the original plaintext!")
		}
	}
	fmt.Println("Successfully recovered plaintext!")
}
