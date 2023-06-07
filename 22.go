package main

import (
	"fmt"
	"time"
)

func main() {
	// wait a lil
	duration := randInt(40, 1000)
	time.Sleep(time.Duration(duration) * time.Second)

	mt := &MT19937{}
	now := time.Now().Unix()
	mt.Init(uint32(now))

	time.Sleep(time.Duration(randInt(40, 1000)) * time.Second)
	x, err := mt.Rand()

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(x)
}