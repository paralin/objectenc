package aes

import (
	"crypto/rand"

	"github.com/multiformats/go-multihash"
	"github.com/pkg/errors"
)

// KeyHashSaltLen is the length of the key hash salt in bytes
const KeyHashSaltLen = 32

// HashKey hashes a AES key with a multihash.
// keyHashSaltPtr is optional, but if set will either use the value or overwrite it if empty.
// hashCode is the code from multihash, or we will use sha1 on default.
func HashKey(keyData []byte, keyHashSaltPtr *[]byte, hashCode uint64) (multihash.Multihash, error) {
	if hashCode == 0 {
		hashCode = multihash.SHA1
	}

	var keyHashSalt []byte
	if keyHashSaltPtr != nil {
		keyHashSalt = *keyHashSaltPtr
	}
	if len(keyHashSalt) == 0 {
		keyHashSalt = make([]byte, KeyHashSaltLen)
		if _, err := rand.Read(keyHashSalt); err != nil {
			return nil, err
		}
		if keyHashSaltPtr != nil {
			*keyHashSaltPtr = keyHashSalt
		}
	} else if len(keyHashSalt) != KeyHashSaltLen {
		return nil, errors.Errorf("expected key hash salt length %d != actual %d", KeyHashSaltLen, len(keyHashSalt))
	}

	saltKey := make([]byte, len(keyHashSalt)+len(keyData))
	copy(saltKey[:len(keyHashSalt)], keyHashSalt)
	copy(saltKey[len(keyHashSalt):], keyData)

	return multihash.Sum(saltKey, hashCode, -1)
}
