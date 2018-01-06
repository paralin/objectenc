package objectenc

import (
	"context"

	"github.com/pkg/errors"
)

// ResourceResolverFunc resolves resources related to encrypted blobs if needed.
// resourceCtr is the "resource container" as specified by the encryption implementation.
// an effective implementation of this function is a type switch on the resource ctr.
type ResourceResolverFunc func(ctx context.Context, blob *EncryptedBlob, resourceCtr interface{}) error

// Validate checks the blob to see if it "looks ok" without actually decrypting it.
func (b *EncryptedBlob) Validate() error {
	if b == nil {
		return errors.New("blob is empty")
	}

	impl, err := GetEncryptionImpl(b.GetEncType())
	if err != nil {
		return err
	}
	if err := impl.ValidateMetadata(b.GetEncMetadata()); err != nil {
		return errors.WithMessage(err, "invalid metadata field")
	}
	return nil
}

// Decrypt attempts to decrypt the encrypted blob, assuming no resources will need to be resolved.
func (b *EncryptedBlob) Decrypt() ([]byte, error) {
	return b.DecryptWithResolver(context.Background(), nil)
}

// DecryptWithResolver decrypts the encrypted blob with a resource resolver attached.
func (b *EncryptedBlob) DecryptWithResolver(ctx context.Context, resolver ResourceResolverFunc) ([]byte, error) {
	impl, err := GetEncryptionImpl(b.GetEncType())
	if err != nil {
		return nil, err
	}

	return impl.DecryptBlob(ctx, resolver, b)
}

// Encrypt attempts to encrypt a blob, assuming no resources will need to be resolved.
func Encrypt(encType EncryptionType, blob []byte) (*EncryptedBlob, error) {
	return EncryptWithResolver(context.Background(), nil, encType, blob)
}

// EncryptWithResolver encrypts the blob with a resource resolver attached.
func EncryptWithResolver(
	ctx context.Context,
	resolver ResourceResolverFunc,
	encType EncryptionType,
	data []byte,
) (*EncryptedBlob, error) {
	impl, err := GetEncryptionImpl(encType)
	if err != nil {
		return nil, err
	}

	b, err := impl.EncryptBlob(ctx, resolver, data)
	if err != nil {
		return nil, err
	}

	b.EncType = encType
	return b, nil
}
