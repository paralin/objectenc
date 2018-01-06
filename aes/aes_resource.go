package aes

import (
	"github.com/aperturerobotics/objectenc/resources"
)

// KeySaltMultihash is a key multihash and salt.
type KeySaltMultihash = resources.KeySaltMultihash

// KeyResource looks up a key given a KeySaltMultihash.
type KeyResource = resources.KeyResource

// EncryptMetaResource looks up the metadata needed for encrypting.
type EncryptMetaResource struct {
	// Data is the data we are currently trying to encrypt.
	Data []byte
	// KeyData is the AES key.
	// Filled by resolver.
	KeyData []byte
	// KeyHashSalt is the key hash salt to use.
	// It may be desired to deduplicate this between objects to save compute power.
	// len(KeyHashSalt) MUST equal KeyHashSaltLen
	KeyHashSalt []byte
	// KeyMultihash sets a pre-computed key multihash with the salted prefix given in KeyHashSalt.
	KeyMultihash []byte
}
