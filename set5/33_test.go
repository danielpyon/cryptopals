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

func Test33Big(t *testing.T) {
	p := new(big.Int)
	p.SetString("0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)
	g := big.NewInt(2)

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
