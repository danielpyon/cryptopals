package main

import (
	"fmt"
	"encoding/hex"
)

func main() {
	padded := PadPkcs7([]byte("YELLOW SUBMARINE"), 20)
	fmt.Println(hex.EncodeToString(padded))
}

