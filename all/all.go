package all

import (
	"github.com/aperturerobotics/objectenc"
	"github.com/aperturerobotics/objectenc/aes"
	"github.com/aperturerobotics/objectenc/secretbox"

	// _ imports snappy compression
	_ "github.com/aperturerobotics/objectenc/snappy"
	// _ "github.com/aperturerobotics/objectenc/blowfish"
)

// GetImplementations returns all known implementations.
func GetImplementations() []objectenc.EncryptionImpl {
	return []objectenc.EncryptionImpl{
		&aes.AES{},
		&secretbox.SecretBox{},
	}
}
