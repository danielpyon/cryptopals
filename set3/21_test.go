package set3

import (
	"testing"

	"github.com/danielpyon/cryptopals/lib"
)

func Test21(t *testing.T) {
	mt := &lib.MT19937{}
	var seed uint32 = 19650218
	mt.Init(seed)
	x, err := mt.Rand()

	if err != nil {
		t.Errorf("could not get pseudorandom number")
	}

	if x != 2325592414 {
		t.Errorf("prng is incorrect!")
	}
}
