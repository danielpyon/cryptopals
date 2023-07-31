package set5

import (
	"math/big"
	"testing"

	"github.com/danielpyon/cryptopals/set2"
)

func Test33(t *testing.T) {
	p := big.NewInt(37)
	g := big.NewInt(5)

	// generate a, b
	a := big.NewInt(set2.RandInt(0, g.Int64()-1))
	b := big.NewInt(set2.RandInt(0, g.Int64()-1))

	// find A, B
	var A big.Int
	A.Exp(g, a, p)

	var B big.Int
	B.Exp(g, b, p)

	// compute shared key
	var sA big.Int
	sA.Exp(&B, a, p)
	var sB big.Int
	sB.Exp(&A, b, p)

	if sA.Cmp(&sB) != 0 {
		t.Errorf("keys are not equal")
	}
}
