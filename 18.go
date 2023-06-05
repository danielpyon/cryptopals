package main

func main() {
	EncryptAesCtr(make([]byte, 16*8+14), []byte("YELLOW SUBMARINE"), 0)
}