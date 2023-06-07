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
		1. y ^= (y >> u)
		2. y ^= ((y << s) & b)
		3. y ^= ((y << t) & c)
		4. y ^= (y >> l)
		*/

		val, err := mt.Rand()

		if err != nil {
			panic("failed on mt.Rand()")
		}

		// y ^= (y >> l)
		// abcdefghijklmnopqrstuvwxyz123456
		// 000000000000000000abcdefghijklmn
		// abcdefghijklmnopqr--------------
		val ^= (val >> MT19937_L)

		// y ^= ((y << t) & c), t = 15, c = 0xefc60000
		// abcdefghijklmnopqrstuvwxyz123456
		// first, left shift by 15
		// pqrstuvwxyz123456000000000000000

		// then, apply AND mask
		// pqrstuvwxyz123456000000000000000
		// AND
		// 11101111110001100000000000000000
		// =
		// pqr0tuvwxy0003400000000000000000
		
		// so we need to left shift the value by 15
		// then AND it with the mask,
		// then XOR it with our value
		val ^= (val << MT19937_T) & MT19937_C
		
		// y ^= ((y << s) & b), s = 7, b = 0x9d2c5680
		// abcdefghijklmnopqrstuvwxyz123456
		// hijklmnopqrstuvwxyz1234560000000
		// 10011101001011000101011010000000
		// h00klm0o00r0tu000y01034060000000

		// which bits are preserved / recoverable (+ means recoverable)?
		// -bc-+-g+ij-l-+opq-s+u++x+z123456
		// then,
		// x[0] = a ^ h (we know h)
		// x[3] = d ^ k (can deduce)
		// x[5] = f ^ m (can deduce)
		// x[10] = k ^ r (can deduce)
		// x[12] = m ^ t (we know t)
		// x[17] = r ^ y (we know y)

		// first, apply the mask
		// at this point, we have
		// -bc-e-ghij-l-nopq-stuvwxyz123456
		val ^= (val << MT19937_S) & MT19937_B

		// x[0] = a ^ h (we know h)
		val ^= ((val & 0x1000000) << 7)
		// x[12] = m ^ t (we know t)
		val ^= ((val & 0x1000) << 7)
		// x[17] = r ^ y (we know y)
		val ^= ((val & 0x80) << 7)

		// now, we have
		// abc-e-ghij-lmnopqrstuvwxyz123456

		// x[10] = k ^ r (can deduce)
		val ^= ((val & 0x4000) << 7)
		// abc-e-ghijklmnopqrstuvwxyz123456
		
		// x[3] = d ^ k (can deduce)
		val ^= ((val & 0x200000) << 7)
		// abcde-ghijklmnopqrstuvwxyz123456

		// x[5] = f ^ m (can deduce)
		val ^= ((val & 0x80000) << 7)
		// abcdefghijklmnopqrstuvwxyz123456



		// y ^= (y >> u), u = 11
		// abcdefghijklmnopqrstuvwxyz123456
		// 00000000000abcdefghijklmnopqrstu
		// abcdefghijk+++++++++++----------

		val ^= (val >> MT19937_U) & 0x1ffc00
		// at this point, we have
		// abcdefghijklmnopqrstuv----------
		val ^= (val >> 11) & 0x3ff

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