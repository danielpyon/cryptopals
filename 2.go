package main

import (
	"fmt"
	"errors"
	"bytes"
	"encoding/hex"
	b64 "encoding/base64"
)

// Converts a hex string to base64
func hex_to_base64(input string) (string, error) {
	// First, convert the input string into byte[]
	bytes, err := hex.DecodeString(input)
	if err != nil {
		return "", err
	}

	// Then, convert the bytes into base64
	encoded := b64.StdEncoding.EncodeToString(bytes)
	return encoded, nil
}

func xor(a, b []byte) ([]byte, error) {
	length := len(a)
	if length != len(b) {
		return nil, errors.New("lengths are not equal")
	}

	c := make([]byte, length)
	for i := 0; i < length; i++ {
		c[i] = a[i] ^ b[i]
	}

	return c, nil
}

func main() {
	a, _ := hex.DecodeString("1c0111001f010100061a024b53535009181c")
	b, _ := hex.DecodeString("686974207468652062756c6c277320657965")

	var c []byte
	var err error
	if c, err = xor(a, b); err != nil {
		fmt.Println("Failed: ", err)
		return
	}

	answer, _ := hex.DecodeString("746865206b696420646f6e277420706c6179")
	if bytes.Equal(c, answer) {
		fmt.Println("Correct!")
	} else {
		fmt.Println("Incorrect!")
	}
}

