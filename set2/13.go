package set2

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/danielpyon/cryptopals/lib"
)

func ParseKeyValue(str string) ([]byte, error) {
	tokens := strings.Split(str, "&")

	kvs := make(map[string]interface{})
	for _, token := range tokens {
		kv := strings.Split(token, "=")
		k, v := kv[0], kv[1]

		// parse ints
		i, err := strconv.Atoi(v)
		if err != nil {
			kvs[k] = v
		} else {
			kvs[k] = i
		}
	}

	ret, err := json.Marshal(kvs)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func ProfileFor(email string) string {
	// delete &, = from email
	email = strings.Replace(email, "&", "", -1)
	email = strings.Replace(email, "=", "", -1)
	encoded := "email=" + email + "&uid=10&role=user"
	return encoded
}

func EncryptProfile(email string, key []byte) []byte {
	encoded := []byte(ProfileFor(email))
	padded := lib.PadPkcs7(encoded, 16)

	encryptedProfile, err := lib.EncryptAesEcb(padded, key)
	if err != nil {
		panic(err)
	}

	return encryptedProfile
}

func DecryptProfile(encryptedProfile, key []byte) []byte {
	profile, err := lib.DecryptAesEcb(encryptedProfile, key)
	if err != nil {
		panic(err)
	}

	unpadded, err := lib.UnpadPkcs7(profile)
	if err != nil {
		panic(err)
	}

	profileStr := lib.BytesToString(unpadded)
	kvs, err := ParseKeyValue(profileStr)
	if err != nil {
		panic(err)
	}

	return kvs
}

// check if we have successfully gotten admin role
func Check(profile, key []byte) bool {
	decrypted := DecryptProfile(profile, key)

	var decoded map[string]interface{}
	if err := json.Unmarshal(decrypted, &decoded); err != nil {
		return false
	}

	if decoded["role"] == "admin" {
		return true
	}
	return false
}
