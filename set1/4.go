package set1

import (
	"errors"
)

func HammingDistance(a, b []byte) (int, error) {
	if len(a) != len(b) {
		return 0, errors.New("differing lengths of bytes")
	}

	hamming_dist := 0
	length := len(a)
	for i := 0; i < length; i++ {
		xor := a[i] ^ b[i]
		// count the number of ones in xor
		// because this is the number of differing bit positions
		dist := 0
		for j := 0; j < 8; j++ {
			if xor&1 == 1 {
				dist++
			}
			xor >>= 1
		}

		hamming_dist += dist
	}

	return hamming_dist, nil
}
