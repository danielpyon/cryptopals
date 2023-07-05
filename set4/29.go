package set4

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/danielpyon/cryptopals/lib/sha1"
)

// we need to know the length of the original message because that's part of
// the internal state of sha1 (struct digest in sha1.go)

// tag := SHA-1(key || original-message || new-message)

// Returns whether the sum is a valid MAC tag for the message
func Sha1Validate(key, message, sum []byte) bool {
	tmp := sha1.Sum(append(key, message...))

	for i, _ := range sum {
		if tmp[i] != sum[i] {
			return false
		}
	}

	return true
}

// Returns SHA1 padded message
// The length is padded with zeros until it's congruent to 448 mod 512 bits
// Then the last 64 bits is the length of the message
func Sha1Padding(data []byte) []byte {
	bytesNeeded := len(data) % 64
	if bytesNeeded > 56 {
		bytesNeeded += 8
	}
	bytesNeeded = (56 - bytesNeeded) % 64

	padded := append(
		data,
		bytes.Repeat([]byte("\x00"), bytesNeeded)...,
	)
	padded = binary.LittleEndian.AppendUint64(padded, uint64(len(data)))
	return padded
}

// Recover the internal state from a checksum
func Sha1RecoverState(sum [sha1.Size]byte) [5]uint32 {
	return nil
}

// Returns a forged SHA1 MAC tag for a given message and extension
func Sha1LengthExtension(sum [sha1.Size]byte, message, extension, key []byte, length uint64) ([]byte, error) {
	// the registers used in sha1
	state := Sha1RecoverState(sum)

	for keyLen := 0; keyLen <= 32; keyLen++ {
		newMessage := bytes.Repeat([]byte("A"), keyLen)
		newMessage = Sha1Padding(append(newMessage, message...))

		h := sha1.NewExtension(state, uint64(len(newMessage)))
		n, err := h.Write(extension)
		if err != nil || n != len(extension) {
			return nil, err
		}

		newSum := h.Sum(nil)
		if Sha1Validate(key, newMessage[keyLen:], newSum) {
			return newSum, nil
		}
	}

	return nil, errors.New("Could not forge tag!")
}
