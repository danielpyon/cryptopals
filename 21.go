package main

import (
	"fmt"
)

func main() {
	mt := &MT19937{}
	mt.Init(1131464071)
	x, err := mt.Rand()

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(x)
}