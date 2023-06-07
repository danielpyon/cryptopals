package main

import (
	"fmt"
	"time"
)

// given an MT19937, clone it (just based on the outputs, not the internal state)
func CloneMT19937(mt *MT19937) *MT19937 {
	internalState := make([]uint32, MT19937_N)

	// the internal index will go from 0 to 624, and every time we call rand,
	// we get a value to reverse. this will be the state array at the index.
	for index := uint32(0); index < MT19937_N; index++ {
		/*
		we want to reverse this:

		0. y = MT[index]
		1. y_new = y_old ^ (y_old >> u)
		2. y_new = y_old ^ ((y_old << s) & b)
		3. y_new = y_old ^ ((y_old << t) & c)
		4. y_new = y_old ^ (y_old >> l)
		*/

		// 4. y_new = y_old ^ (y_old >> l)
		// 11110101010101011111010101010101
		// 00000000000000000011110101010101
		// the top l bits are part of y_old
		// then, XOR the bottom 32-l bits with the top 32-l bits
		val, err := mt.Rand()

		if err != nil {
			panic("failed on mt.Rand()")
		}

		val ^= (val >> MT19937_L)
		val ^= (val << MT19937_T) & MT19937_C
		val ^= (val << MT19937_S) & MT19937_B
		val ^= (val >> MT19937_U)
		internalState[index] = val
	}

	// the internal state of the clone should be equal to mt's state AFTER
	// Init() (and twist()), so we should set the index to 0 (and don't call
	// Init()).
	clone := &MT19937{}
	clone.MT = internalState
	clone.index = 0

	return clone
}

func main() {
	fmt.Println("[+] === chall 23 ===")

	// first, make an MT
	seed := uint32(time.Now().Unix())
	mt := &MT19937{}
	mt.Init(seed)

	mtClone := CloneMT19937(mt)

	// check some values to make sure they're really the same
	mtOrig := &MT19937{} // make another mt because we called Rand on the other one
	mtOrig.Init(seed) // same seed

	for i := 0; i < 600; i++ {
		orig, err := mtOrig.Rand()
		if err != nil {
			panic("could not generate random number!")
		}
		clone, err := mtClone.Rand()
		if err != nil {
			panic("could not generate random number!")
		}
		
		if (orig != clone) {
			panic("the clone is not accurate!")
		}
	}

	fmt.Println("the clone is accurate!")
}