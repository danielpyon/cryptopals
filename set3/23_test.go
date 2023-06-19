package set3

import (
	"fmt"
	"testing"
	"time"

	"github.com/danielpyon/cryptopals/lib"
)

func Test23(t *testing.T) {
	fmt.Println("[+] === chall 23 ===")

	// first, make an MT
	seed := uint32(time.Now().Unix())
	mt := &lib.MT19937{}
	mt.Init(seed)

	mtClone := CloneMT19937(mt)

	// check some values to make sure they're really the same
	mtOrig := &lib.MT19937{} // make another mt because we called Rand on the other one
	mtOrig.Init(seed)        // same seed

	for i := 0; i < 600; i++ {
		orig, err := mtOrig.Rand()
		if err != nil {
			t.Errorf("could not generate random number!")
		}
		clone, err := mtClone.Rand()
		if err != nil {
			t.Errorf("could not generate random number!")
		}

		if orig != clone {
			t.Errorf("the clone is not accurate!")
		}
	}

	fmt.Println("the clone is accurate!")
}
