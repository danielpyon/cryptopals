package main

import (
	"fmt"
)

func main() {
	mt := &MT19937{}
	mt.Init(19650218)
	x, err := mt.Rand()

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(x)
}