package set3

import (
	"fmt"
	"testing"
	"time"

	"github.com/danielpyon/cryptopals/lib"
	"github.com/danielpyon/cryptopals/set2"
)

func Test22(t *testing.T) {
	lo, hi := int64(2), int64(4)

	// wait a lil
	duration := set2.RandInt(lo, hi)
	time.Sleep(time.Duration(duration) * time.Second)

	mt := &lib.MT19937{}
	now := time.Now().Unix()
	fmt.Printf("seed: %v\n", now)

	mt.Init(uint32(now))

	time.Sleep(time.Duration(set2.RandInt(lo, hi)) * time.Second)
	x, err := mt.Rand()

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(x)
}
