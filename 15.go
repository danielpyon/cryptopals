package main

import (
	"fmt"
	"encoding/hex"
)

func Test(input []byte, testCaseNum int) {
	result, err := UnpadPkcs7(input)
	if err != nil {
		fmt.Printf("Could not unpad message #%v\n", testCaseNum)
	} else {
		fmt.Printf("Successfully unpadded #%v\n", testCaseNum)
		fmt.Println(BytesToString(result))
		fmt.Println(hex.EncodeToString(result))
	}
}

func main () {
	fmt.Println("[+] === chall 15 ===")
	// should succeed
	Test([]byte("ICE ICE BABY\x04\x04\x04\x04"), 1)
	// should fail
	Test([]byte("ICE ICE BABY\x05\x05\x05\x05"), 2)
	// should fail
	Test([]byte("ICE ICE BABY\x01\x02\x03\x04"), 3)
}
