package set4

import (
	"fmt"
	"testing"
)

func Test29(t *testing.T) {
	x := 56
	x %= 64
	if x > 56 {
		x += 8
	}
	bn := (56 - x) % 64

	if bn < 0 {
		panic("fail")
	}
	fmt.Println(bn)
}
