/* Copyright 2023 Daniel Pyon
 * This is the core crypto library, written from scratch.
 */

package main

import (
	"encoding/hex"
	"errors"
	"math"
	"fmt"
	"sort"
	"strings"
	b64 "encoding/base64"
)

// Converts a hex string to base64
func HexToBase64(input string) string {
	// First, convert the input string into byte[]
	bytes, err := hex.DecodeString(input)
	if err != nil {
		panic(err)
	}

	// Then, convert the bytes into base64
	encoded := b64.StdEncoding.EncodeToString(bytes)
	return encoded
}

// XOR byte-by-byte
func XOR(a, b []byte) ([]byte, error) {
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

// Give a score to some English text. Higher score means more likely to be valid English
func ScoreEnglish(text string) float64 {
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

	// If frequency of alphabetic + space is too low, penalize score
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

// Fill all bytes of input array with specified byte
func FillArray(arr []byte, val byte) {
	for i, _ := range(arr) {
		arr[i] = val
	}
}

// Convert byte array to string (note that they're bytes, not runes)
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

// Rank mappings of english sentence -> score
func RankByScore(scores map[string]float64) PairList {
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

func RepeatingKeyXOR(input, key []byte) {
	for i, v := range input {
		input[i] = v ^ key[i % len(key)]
	}
}

