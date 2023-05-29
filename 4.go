package main

import (
	"fmt"
	"math"
	"errors"
	"strings"
	"sort"
	"encoding/hex"
	"io/ioutil"
	b64 "encoding/base64"
)

// Converts a hex string to base64
func hexToBase64(input string) (string, error) {
	// First, convert the input string into byte[]
	bytes, err := hex.DecodeString(input)
	if err != nil {
		return "", err
	}

	// Then, convert the bytes into base64
	encoded := b64.StdEncoding.EncodeToString(bytes)
	return encoded, nil
}

func xor(a, b []byte) ([]byte, error) {
	length := len(a)
	if length != len(b) {
		return nil, errors.New("lengths are not equal")
	}

	c := make([]byte, length)
	for i := 0; i < length; i++ {
		c[i] = a[i] ^ b[i]
	}

	return c, nil
}

var ENGLISH_FREQS = map[rune]float64{
	'T' : .0910,
	'E' : .1200,
	'A' : .0812,
	'O' : .0768,
	'I' : .0731,
	'N' : .0695,
	'S' : .0628,
	'R' : .0602,
	'H' : .0592,
	'D' : .0432,
	'L' : .0398,
	'U' : .0288,
	'C' : .0271,
	'M' : .0261,
	'F' : .0230,
	'Y' : .0211,
	'W' : .0209,
	'G' : .0203,
	'P' : .0182,
	'B' : .0149,
	'V' : .0111,
	'K' : .0069,
	'X' : .0017,
	'Q' : .0011,
	'J' : .0010,
	'Z' : .0007,
}

// Higher score means more likely to be valid English
func score(text string) float64 {
	// Compute frequencies of letters
	text = strings.ToUpper(text)
	freqs := make(map[rune]float64)
	var num_alphabetic int = 0
	var num_spaces int = 0
	for _, ch := range text {
		if _, ok := freqs[ch]; ok {
			freqs[ch]++
		} else {
			freqs[ch] = 1.0
		}

		// check if it's alphabetic
		if _, ok := ENGLISH_FREQS[ch]; ok {
			num_alphabetic++
		}
		if ch == ' ' {
			num_spaces++
		}
	}

	ratio := float64(num_alphabetic + num_spaces) / float64(len(text))
	if ratio <= 0.8 {
		return -math.MaxFloat64
	}

	for k := range freqs {
		freqs[k] /= float64(num_alphabetic)
	}

	// Compute distance from actual English frequencies
	var score float64 = 0
	for k := range freqs {
		if _, ok := ENGLISH_FREQS[k]; ok {
			curr_letter_diff := freqs[k] - ENGLISH_FREQS[k]
			score += curr_letter_diff * curr_letter_diff
		}
	}

	score = -math.Sqrt(score)
	return score
}

func fillArray(arr []byte, val byte) {
	for i, _ := range(arr) {
		arr[i] = val
	}
}

func BytesToString(x []byte) string {
	var sb strings.Builder
	for i := 0; i < len(x); i++ {
		sb.WriteString("%c")
	}
	format_str := sb.String()

	tmp := make([]interface{}, len(x))
	for i, val := range x {
		tmp[i] = val
	}
	return fmt.Sprintf(format_str, tmp...)
}

func rankByScore(scores map[string]float64) PairList {
	pl := make(PairList, len(scores))
	i := 0
	for k, v := range scores {
		pl[i] = Pair{k, v}
		i++
	}
	sort.Sort(sort.Reverse(pl))
	return pl
}

type Pair struct {
	Key string
	Value float64
}

type PairList []Pair
func (p PairList) Len() int { return len(p) }
func (p PairList) Less(i, j int) bool { return p[i].Value < p[j].Value }
func (p PairList) Swap(i, j int) { p[i], p[j] = p[j], p[i] }

func ParseInputFile() [][]byte {
	data, err := ioutil.ReadFile("4.txt")
	if err != nil {
		panic("failed to read file!")
	}
	split := strings.Split(string(data), "\n")
	ret := make([][]byte, len(split))
	for i, s := range split {
		bytes, err := hex.DecodeString(s)
		if err != nil {
			panic("couldn't decode string!")
		}
		ret[i] = bytes
	}
	return ret
}

func main() {
	// array of ciphertexts
	cts := ParseInputFile()
	
	// map from string to its score
	scores := make(map[string]float64)
	
	// populate scores map
	for _, ct := range cts {
		// for each ciphertext, compute scores with all possible keys
		var key byte
		for key = 0; key < 255; key++ {
			mask := make([]byte, len(ct))
			fillArray(mask, key)
	
			result, err := xor(ct, mask)
			if err != nil {
				panic("not same length")
			}
	
			plaintext := BytesToString(result)
			scores[plaintext] = score(plaintext)
		}
	}

	ranked := rankByScore(scores)
	i := 0
	for _, pr := range ranked {
		if i >= 10 {
			break
		}

		if pr.Value == 0.0 {
			continue
		} else {
			i++
		}

		fmt.Println("String: ", pr.Key, " Value: ", pr.Value)
	}
	fmt.Println()
}
