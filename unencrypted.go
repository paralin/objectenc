package objectenc

import (
	"context"
	"github.com/pkg/errors"
)

// Passthrough is the pass-through encryption implementation.
type Passthrough struct{}

// GetEncryptionType returns the encryption type this implementation satisfies.
func (p *Passthrough) GetEncryptionType() EncryptionType {
	return EncryptionType_EncryptionType_UNENCRYPTED
}

// ValidateMetadata checks the metadata field.
// If metadata is not expected, this should check that it doesn't exist.
func (p *Passthrough) ValidateMetadata(meta []byte) error {
	if len(meta) != 0 {
		return errors.New("metadata not expected for unencrypted object")
	}

	return nil
}

// DecryptBlob decrypts an encrypted blob.
func (p *Passthrough) DecryptBlob(_ context.Context, _ ResourceResolverFunc, blob *EncryptedBlob) ([]byte, error) {
	return blob.GetEncData(), nil
}

// EncryptBlob encrypts a blob.
func (p *Passthrough) EncryptBlob(_ context.Context, _ ResourceResolverFunc, data []byte) (*EncryptedBlob, error) {
	return &EncryptedBlob{EncType: p.GetEncryptionType(), EncData: data}, nil
}

func init() {
	MustRegisterEncryptionImpl(&Passthrough{})
}
