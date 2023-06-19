package main

import (
	"fmt"
	"time"
)

func main() {
	lo, hi := int64(2), int64(4)

	// wait a lil
	duration := randInt(lo, hi)
	time.Sleep(time.Duration(duration) * time.Second)

	mt := &MT19937{}
	now := time.Now().Unix()
	fmt.Printf("seed: %v\n", now)

	mt.Init(uint32(now))

	time.Sleep(time.Duration(randInt(lo, hi)) * time.Second)
	x, err := mt.Rand()

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(x)
}