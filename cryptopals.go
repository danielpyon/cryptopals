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
	"crypto/aes"
	"io/ioutil"
	"crypto/rand"
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

// Read base64 file and turn it into []byte
func ReadBase64EncodedFile(filename string) ([]byte, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	split := strings.Split(string(data), "\n")
	var result string
	for _, s := range split {
		result += s
	}

	dec, err := b64.StdEncoding.DecodeString(result)
	if err != nil {
		return nil, err
	}

	return dec, nil
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

func XorInPlace(dst, src []byte) error {
	length := len(dst)
	if length != len(src) {
		return errors.New("lengths are not equal")
	}
	for i, _ := range dst {
		dst[i] = dst[i] ^ src[i]
	}
	return nil
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

func FillSlice[T any](arr []T, val T) {
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

// Rank mappings of plaintext -> score
func RankByScore(scores map[string]float64) PairList {
	rankings := make(PairList, len(scores))
	i := 0
	for k, v := range scores {
		rankings[i] = Pair{k, v}
		i++
	}
	sort.Sort(sort.Reverse(rankings))
	return rankings
}

type Pair struct {
	Plaintext string
	Score float64
}

type PairList []Pair
func (p PairList) Len() int { return len(p) }
func (p PairList) Less(i, j int) bool { return p[i].Score < p[j].Score }
func (p PairList) Swap(i, j int) { p[i], p[j] = p[j], p[i] }

func RepeatingKeyXOR(input, key []byte) {
	for i, v := range input {
		input[i] = v ^ key[i % len(key)]
	}
}

func HammingDistance(a, b []byte) (int, error) {
	if len(a) != len(b) {
		return 0, errors.New("differing lengths of bytes")
	}

	hamming_dist := 0
	length := len(a)
	for i := 0; i < length; i++ {
		xor := a[i] ^ b[i]
		// count the number of ones in xor
		// because this is the number of differing bit positions
		dist := 0
		for j := 0; j < 8; j++ {
			if xor & 1 == 1 {
				dist++
			}
			xor >>= 1
		}

		hamming_dist += dist
	}

	return hamming_dist, nil
}

func BreakSingleXORCipher(ciphertext []byte) string {
	var key byte
	scores := make(map[string]float64)
	for key = 0; key < 255; key++ {
		mask := make([]byte, len(ciphertext))
		FillSlice(mask, key)

		result, err := XOR(ciphertext, mask)
		if err != nil {
			panic("not same length")
		}

		plaintext := BytesToString(result)
		scores[plaintext] = ScoreEnglish(plaintext)
	}

	rankings := RankByScore(scores)
	return rankings[0].Plaintext
}

func BreakSingleXORCipherWithKey(ciphertext []byte) (string, byte) {
	var key byte
	scores := make(map[string]float64)
	plaintext_to_key := make(map[string]byte)
	for key = 0; key < 255; key++ {
		mask := make([]byte, len(ciphertext))
		FillSlice(mask, key)

		result, err := XOR(ciphertext, mask)
		if err != nil {
			panic("not same length")
		}

		plaintext := BytesToString(result)

		scores[plaintext] = ScoreEnglish(plaintext)
		plaintext_to_key[plaintext] = key
	}

	rankings := RankByScore(scores)
	pt := rankings[0].Plaintext
	return pt, plaintext_to_key[pt]
}

/// AES

func DecryptAesEcb(data, key []byte) ([]byte, error) {
	if len(data) % 16 != 0 {
		return nil, errors.New("data length is not a multiple of 16")
	}

	cipher, err := aes.NewCipher(key)
	
	if err != nil {
		return nil, err
	}

	decrypted := make([]byte, len(data))
	size := 16

	for start, end := 0, size; start < len(data); start, end = start+size, end+size {
		cipher.Decrypt(decrypted[start:end], data[start:end])
	}

	return decrypted, nil
}

func EncryptAesEcb(data, key []byte) ([]byte, error) {
	if len(data) % 16 != 0 {
		return nil, errors.New("data length is not a multiple of 16")
	}

	cipher, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	encrypted := make([]byte, len(data))
	size := 16

	for start, end := 0, size; start < len(data); start, end = start+size, end+size {
		cipher.Encrypt(encrypted[start:end], data[start:end])
	}

	return encrypted, nil
}

func PadPkcs7(data []byte, blockSize int) []byte {
	// bytes needed to reach a multiple of blockSize
	bytesNeeded := blockSize - (len(data) % blockSize)

	padded := make([]byte, len(data) + bytesNeeded)
	
	// copy data to padded
	for i, b := range data {
		padded[i] = b
	}

	padByte := byte(bytesNeeded)
	for i := len(data); i < len(data) + bytesNeeded; i++ {
		padded[i] = padByte
	}

	return padded
}

// this modifies the original data
func EncryptAesCbc(data, key []byte) ([]byte, error) {
	if len(data) % 16 != 0 {
		return nil, errors.New("data length is not a multiple of 16")
	}
	
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	encrypted := make([]byte, 16, len(data) + 16)

	// generate the initialization vector
	n, err := rand.Read(encrypted)
	if n != 16 {
		return nil, errors.New("could not generate random bytes")
	}
	
	if err != nil {
		return nil, err
	}

	size := 16
	for start, end := 0, size; start < len(data); start, end = start+size, end+size {
		XorInPlace(data[start:end], encrypted[start:end])
		cipher.Encrypt(encrypted[start+size:end+size], data[start:end])
	}

	return encrypted[:cap(encrypted)], nil
}

func DecryptAesCbc(data, key []byte) ([]byte, error) {
	if len(data) % 16 != 0 {
		return nil, errors.New("data length is not a multiple of 16")
	}
	
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	decrypted := make([]byte, len(data) - 16)

	size := 16
	for start, end := size, size*2; start < len(data); start, end = start+size, end+size {
		// indices into decrypted
		i, j := start-size, end-size
		cipher.Decrypt(decrypted[i:j], data[start:end])
		XorInPlace(decrypted[i:j], data[i:j])
	}

	return decrypted, nil
}


