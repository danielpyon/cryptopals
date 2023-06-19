package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
)

func GetTag(key, message string) []byte {
	tag := sha1.Sum([]byte(key + message))
	return tag[:]
}

func main() {
	key := "yellow submarine"

	fmt.Println(hex.EncodeToString(GetTag(key, "hello world")))
	fmt.Println(hex.EncodeToString(GetTag(key, "hello world!")))
}
