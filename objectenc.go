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

	compImpl, err := GetCompressionImpl(b.GetCompressionType())
	if err != nil {
		return err
	}
	_ = compImpl

	if err := impl.ValidateMetadata(b.GetEncMetadata()); err != nil {
		return errors.WithMessage(err, "invalid metadata field")
	}

	return nil
}

// Decrypt attempts to decrypt the encrypted blob, assuming no resources will need to be resolved.
func (b *EncryptedBlob) Decrypt(ctx context.Context) ([]byte, error) {
	return b.DecryptWithResolver(ctx, nil)
}

// DecryptWithResolver decrypts the encrypted blob with a resource resolver attached.
func (b *EncryptedBlob) DecryptWithResolver(ctx context.Context, resolver ResourceResolverFunc) ([]byte, error) {
	impl, err := GetEncryptionImpl(b.GetEncType())
	if err != nil {
		return nil, err
	}

	decDat, err := impl.DecryptBlob(ctx, resolver, b)
	if err != nil {
		return nil, err
	}

	if b.GetCompressionType() != CompressionType_CompressionType_UNCOMPRESSED {
		compImpl, err := GetCompressionImpl(b.GetCompressionType())
		if err != nil {
			return nil, err
		}

		return compImpl.DecompressBlob(ctx, decDat)
	}

	return decDat, nil
}

// Encrypt attempts to encrypt a blob, assuming no resources will need to be resolved.
func Encrypt(encType EncryptionType, cmpType CompressionType, blob []byte) (*EncryptedBlob, error) {
	return EncryptWithResolver(context.Background(), nil, encType, cmpType, blob)
}

// EncryptWithResolver encrypts the blob with a resource resolver attached.
func EncryptWithResolver(
	ctx context.Context,
	resolver ResourceResolverFunc,
	encType EncryptionType,
	cmpType CompressionType,
	data []byte,
) (*EncryptedBlob, error) {
	impl, err := GetEncryptionImpl(encType)
	if err != nil {
		return nil, err
	}

	dataUncompressed := data
	if cmpType != CompressionType_CompressionType_UNCOMPRESSED {
		cmpImpl, err := GetCompressionImpl(cmpType)
		if err != nil {
			return nil, err
		}

		data, err = cmpImpl.CompressBlob(ctx, data)
		if err != nil {
			return nil, err
		}
	}

	b, err := impl.EncryptBlob(ctx, resolver, data, dataUncompressed)
	if err != nil {
		return nil, err
	}

	b.EncType = encType
	b.CompressionType = cmpType
	return b, nil
}
