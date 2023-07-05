package set4

import (
	"io/ioutil"
	"math/rand"
	"strings"
	"testing"

	"github.com/danielpyon/cryptopals/lib/sha1"
)

func getRandomWord() string {
	contents, err := ioutil.ReadFile("/usr/share/dict/words")
	if err != nil {
		panic("failed to read file")
	}

	lines := strings.Split(string(contents), "\n")
	return lines[rand.Intn(len(lines))]
}

func Test29(t *testing.T) {
	// Get a MAC key
	key := []byte(getRandomWord())

	message := []byte("hello world")
	tag := sha1.Sum(message)

	newMessage := []byte("hello world goodbye world")
	newTag, err := Sha1LengthExtension(tag, message, []byte(" goodbye world"), key)
	if err != nil {
		t.Errorf("%v\n", err)
	}

	if !Sha1Validate(key, newMessage, newTag) {
		t.Errorf("forged tag is wrong!")
	}
}
