package lib

import "errors"

const (
	MT19937_W uint32 = 32
	MT19937_N uint32 = 624
	MT19937_M uint32 = 397
	MT19937_R uint32 = 31
	MT19937_A uint32 = 0x9908b0df
	MT19937_U uint32 = 11
	MT19937_D uint32 = 0xffffffff
	MT19937_S uint32 = 7
	MT19937_B uint32 = 0x9d2c5680
	MT19937_T uint32 = 15
	MT19937_C uint32 = 0xefc60000
	MT19937_L uint32 = 18
	MT19937_F uint32 = 1812433253

	MT19937_LOWER_MASK uint32 = (1 << MT19937_R) - 1
	MT19937_UPPER_MASK uint32 = (^MT19937_LOWER_MASK)
)

type MT19937 struct {
	MT    []uint32
	Index uint32
}

func (mt *MT19937) Init(seed uint32) {
	mt.Index = MT19937_N

	mt.MT = make([]uint32, MT19937_N)
	mt.MT[0] = seed

	for i := uint32(1); i < MT19937_N; i++ {
		mt.MT[i] = (MT19937_F * (mt.MT[i-1] ^ (mt.MT[i-1] >> (MT19937_W - 2)))) + i
	}
}

// should not be public
func (mt *MT19937) twist() {
	for i := uint32(0); i < MT19937_N; i++ {
		x := (mt.MT[i] & MT19937_UPPER_MASK) | (mt.MT[(i+1)%MT19937_N] & MT19937_LOWER_MASK)
		xA := x >> 1
		if x%2 != 0 {
			xA ^= MT19937_A
		}
		mt.MT[i] = mt.MT[(i+MT19937_M)%MT19937_N] ^ xA
	}
	mt.Index = 0
}

func (mt *MT19937) Rand() (uint32, error) {
	if mt.Index >= MT19937_N {
		if mt.Index > MT19937_N {
			return 0, errors.New("generator was never seeded")
		}
		mt.twist()
	}

	y := mt.MT[mt.Index]
	y ^= ((y >> MT19937_U) & MT19937_D)
	y ^= ((y << MT19937_S) & MT19937_B)
	y ^= ((y << MT19937_T) & MT19937_C)
	y ^= (y >> MT19937_L)

	mt.Index++
	return y, nil
}

func EncryptMT19937(data []byte, seed uint16) ([]byte, error) {
	// 1) create a MT19937 object with given seed
	mt := &MT19937{}
	mt.Init(uint32(seed))

	// 2) use the random bytes to encrypt the ciphertext
	encrypted := make([]byte, len(data))
	for i, _ := range data {
		val, err := mt.Rand()
		if err != nil {
			return nil, err
		}
		encrypted[i] = data[i] ^ byte(val)
	}

	return encrypted, nil
}

func DecryptMT19937(data []byte, seed uint16) ([]byte, error) {
	return EncryptMT19937(data, seed)
}
