package lib

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"errors"
)

func DecryptAesEcb(data, key []byte) ([]byte, error) {
	if len(data)%16 != 0 {
		return nil, errors.New("data length is not a multiple of 16")
	}

	cipher, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	decrypted := make([]byte, len(data))
	size := 16

	for start, end := 0, size; start < len(data); start, end = start+size, end+size {
		cipher.Decrypt(decrypted[start:end], data[start:end])
	}

	return decrypted, nil
}

func EncryptAesEcb(data, key []byte) ([]byte, error) {
	if len(data)%16 != 0 {
		return nil, errors.New("data length is not a multiple of 16")
	}

	cipher, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	encrypted := make([]byte, len(data))
	size := 16

	for start, end := 0, size; start < len(data); start, end = start+size, end+size {
		cipher.Encrypt(encrypted[start:end], data[start:end])
	}

	return encrypted, nil
}

func PadPkcs7(data []byte, blockSize int) []byte {
	// bytes needed to reach a multiple of blockSize
	bytesNeeded := blockSize - (len(data) % blockSize)

	padded := make([]byte, len(data)+bytesNeeded)

	// copy data to padded
	for i, b := range data {
		padded[i] = b
	}

	padByte := byte(bytesNeeded)
	for i := len(data); i < len(data)+bytesNeeded; i++ {
		padded[i] = padByte
	}

	return padded
}

// returns slice to passed-in array
func UnpadPkcs7(data []byte) ([]byte, error) {
	// last byte guaranteed to be padding byte
	numPadding := int(data[len(data)-1])

	// the last numPadding bytes should be equal to numPadding
	for i := 0; i < numPadding; i++ {
		if data[len(data)-1-i] != byte(numPadding) {
			return nil, errors.New("invalid padding")
		}
	}

	return data[:len(data)-numPadding], nil
}

// this modifies the original data
func EncryptAesCbc(data, key []byte) ([]byte, error) {
	if len(data)%16 != 0 {
		return nil, errors.New("data length is not a multiple of 16")
	}

	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	encrypted := make([]byte, 16, len(data)+16)

	// generate the initialization vector
	n, err := rand.Read(encrypted)
	if n != 16 {
		return nil, errors.New("could not generate random bytes")
	}

	if err != nil {
		return nil, err
	}

	size := 16
	for start, end := 0, size; start < len(data); start, end = start+size, end+size {
		XorInPlace(data[start:end], encrypted[start:end])
		cipher.Encrypt(encrypted[start+size:end+size], data[start:end])
	}

	return encrypted[:cap(encrypted)], nil
}

func DecryptAesCbc(data, key []byte) ([]byte, error) {
	if len(data)%16 != 0 {
		return nil, errors.New("data length is not a multiple of 16")
	}

	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	decrypted := make([]byte, len(data)-16)

	size := 16
	for start, end := size, size*2; start < len(data); start, end = start+size, end+size {
		// indices into decrypted
		i, j := start-size, end-size
		cipher.Decrypt(decrypted[i:j], data[start:end])
		XorInPlace(decrypted[i:j], data[i:j])
	}

	return decrypted, nil
}

func EncryptAesCtr(data, key []byte, nonce uint64) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	encrypted := make([]byte, len(data)+(16-len(data)%16))

	var i uint64
	for i = 0; i < uint64(len(data)); i += 16 {
		blockNum := i / 16

		// first is the nonce, then the block count
		ctr := make([]byte, 16)
		binary.LittleEndian.PutUint64(ctr[:8], nonce)
		binary.LittleEndian.PutUint64(ctr[8:], blockNum)

		cipher.Encrypt(encrypted[i:i+16], ctr)
		start, end := i, i+16

		if end > uint64(len(data)) {
			end = uint64(len(data))
		}

		if err := XorInPlace(encrypted[start:end], data[start:end]); err != nil {
			return nil, err
		}
	}

	return encrypted[:len(data)], nil
}

func DecryptAesCtr(data, key []byte, nonce uint64) ([]byte, error) {
	return EncryptAesCtr(data, key, nonce)
}

func GenerateAesKey() ([]byte, error) {
	key := make([]byte, 16)
	n, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	if n != 16 {
		return nil, errors.New("could not generate random bytes")
	}
	return key, nil
}
