package set3

import (
	b64 "encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/danielpyon/cryptopals/lib"
)

func Test19(t *testing.T) {
	fmt.Println("[+] === chall 19 ===")

	// get ciphertexts
	data, err := ioutil.ReadFile("19.txt")
	if err != nil {
		panic("could not read file")
	}

	split := strings.Split(string(data), "\n")
	key, err := lib.GenerateAesKey()
	if err != nil {
		panic("failed keygen")
	}

	var cts [][]byte
	for _, s := range split {
		pt, err := b64.StdEncoding.DecodeString(s)
		ct, err := lib.EncryptAesCtr(pt, key, 0)
		if err != nil {
			panic("failed encryption")
		}

		cts = append(cts, ct)

		if err != nil {
			panic("could not decode string")
		}
	}

	for _, ct := range cts {
		// fmt.Println(ct)
		fmt.Println(hex.EncodeToString(ct))
	}

}
