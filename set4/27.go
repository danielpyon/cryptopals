package set4

import (
	"crypto/aes"
	"errors"
	"strings"

	"github.com/danielpyon/cryptopals/lib"
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
		lib.XorInPlace(data[start:end], encrypted[start:end])
		cipher.Encrypt(encrypted[start+size:end+size], data[start:end])
	}

	return encrypted[:cap(encrypted)], nil
}

type CbcOracle struct {
	key []byte
}

func (o *CbcOracle) Init() {
	var err error
	o.key, err = lib.GenerateAesKey()

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

	plaintext := lib.PadPkcs7([]byte(pre+userData+post), 16)

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

	plaintext, err := lib.DecryptAesCbc(ctWithIV, o.key)
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
