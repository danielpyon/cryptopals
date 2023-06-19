package set1

import (
	b64 "encoding/base64"
	"io/ioutil"
	"strings"
)

// Read base64 file and turn it into []byte
func ReadBase64EncodedFile(filename string) ([]byte, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	split := strings.Split(string(data), "\n")
	var result string
	for _, s := range split {
		result += s
	}

	dec, err := b64.StdEncoding.DecodeString(result)
	if err != nil {
		return nil, err
	}

	return dec, nil
}
