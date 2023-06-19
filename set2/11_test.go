package set2

import (
	"fmt"
	"testing"
)

func Test11(t *testing.T) {
	total := 100
	correct := 0
	for i := 0; i < total; i++ {
		if DetectAes() {
			correct++
		}
	}

	percentage := float32(correct) / float32(total) * 100.0
	fmt.Printf("%v%% correct\n", percentage)
}
