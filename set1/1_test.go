package set1

import "testing"

func Test1(t *testing.T) {
	encoded := HexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	correctAnswer := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

	if encoded != correctAnswer {
		t.Errorf("Incorrect base64 value")
	}
}
