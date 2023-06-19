package set1

import (
	b64 "encoding/base64"
	"encoding/hex"
)

// Converts a hex string to base64
func HexToBase64(input string) string {
	// First, convert the input string into byte[]
	bytes, err := hex.DecodeString(input)
	if err != nil {
		panic(err)
	}

	// Then, convert the bytes into base64
	encoded := b64.StdEncoding.EncodeToString(bytes)
	return encoded
}
