package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
)

func main() {
	key := "yellow submarine"

	tag1 := sha1.Sum([]byte(key + "hello world"))
	fmt.Println(hex.EncodeToString(tag1[:]))

	tag2 := sha1.Sum([]byte(key + "hello world!"))
	fmt.Println(hex.EncodeToString(tag2[:]))
}
