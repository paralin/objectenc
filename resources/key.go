package resources

import (
	"github.com/aperturerobotics/objectenc"
	"github.com/multiformats/go-multihash"
)

// KeySaltMultihash is a key multihash and salt.
type KeySaltMultihash interface {
	// GetKeyMultihash returns the key multihash or nil of it is invalid.
	GetKeyMultihash() multihash.Multihash
	// GetKeyMultihashSalt returns the key multihash salt.
	GetKeyMultihashSalt() []byte
}

// KeyResource looks up a key given a KeySaltMultihash.
type KeyResource struct {
	// KeySaltMultihash is the key multihash with a prefixed salt.
	KeySaltMultihash KeySaltMultihash
	// EncryptionType is the expected encryption type.
	EncryptionType objectenc.EncryptionType
	// Encrypting indicates if we are encrypting or decrypting.
	Encrypting bool
	// EncryptingData contains the data we are encrypting, of we are.
	EncryptingData []byte

	// KeyData is the resolved key data.
	// Filled by resolver.
	KeyData []byte
}
