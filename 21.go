package main

import (
	"fmt"
)

func main() {
	mt := &MT19937{}
	var seed uint32 = 19650218
	mt.Init(seed)
	x, err := mt.Rand()

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%d\n", x)
}
