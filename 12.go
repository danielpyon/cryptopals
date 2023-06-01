package main

import (
	"fmt"
)

// oracle with persistent key
type PersistentAesOracle struct {
	key []byte
}

func (o *PersistentAesOracle) Init() {
	o.key, _ = GenerateAesKey()
}

func (o *PersistentAesOracle) Encrypt() {

}

func main() {
	fmt.Println("chall 12")
}