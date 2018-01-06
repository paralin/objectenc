package all

import (
	"github.com/aperturerobotics/objectenc"
	"github.com/aperturerobotics/objectenc/aes"
	// _ "github.com/aperturerobotics/objectenc/blowfish"
)

// GetImplementations returns all known implementations.
func GetImplementations() []objectenc.EncryptionImpl {
	return []objectenc.EncryptionImpl{
		&aes.AES{},
	}
}
