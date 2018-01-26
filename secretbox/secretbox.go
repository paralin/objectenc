package secretbox

import (
	"context"

	"github.com/aperturerobotics/objectenc"
	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	nsb "golang.org/x/crypto/nacl/secretbox"
)

// SecretBox is the SecretBox encryption implementation.
type SecretBox struct{}

// GetEncryptionType returns the encryption type this implementation satisfies.
func (a *SecretBox) GetEncryptionType() objectenc.EncryptionType {
	return objectenc.EncryptionType_EncryptionType_SECRET_BOX
}

// ValidateMetadata checks the metadata field.
func (a *SecretBox) ValidateMetadata(data []byte) error {
	m, err := parseMetadata(data)
	if err != nil {
		return err
	}

	if err := m.Validate(); err != nil {
		return err
	}

	return nil
}

// resolveSecretBoxResource resolves the cipher
func (a *SecretBox) resolveSecretBoxResource(
	ctx context.Context,
	resolver objectenc.ResourceResolverFunc,
	blob *objectenc.EncryptedBlob,
	encryptDat []byte,
	encryptDatUncompressed []byte,
) (*SecretBoxResource, error) {
	if resolver == nil {
		return nil, errors.New("resolver required to lookup secretbox key and nonce")
	}

	secretBoxResource := &SecretBoxResource{}
	if encryptDat != nil {
		secretBoxResource.Message = encryptDatUncompressed
	} else if blob != nil {
		secretBoxResource.Box = blob.GetEncData()
	}

	if err := resolver(ctx, blob, secretBoxResource); err != nil {
		return nil, err
	}

	if secretBoxResource.Key == nil || secretBoxResource.Nonce == nil {
		return nil, errors.New("secret box key and nonce must be provided")
	}

	return secretBoxResource, nil
}

// DecryptBlob decrypts an encrypted blob.
// Resolves the resource SecretBoxResource.
func (a *SecretBox) DecryptBlob(ctx context.Context, resolver objectenc.ResourceResolverFunc, blob *objectenc.EncryptedBlob) ([]byte, error) {
	m, err := parseMetadata(blob.GetEncMetadata())
	if err != nil {
		return nil, err
	}
	_ = m

	secretBoxResource, err := a.resolveSecretBoxResource(ctx, resolver, blob, nil, nil)
	if err != nil {
		return nil, err
	}

	if len(blob.GetEncData()) <= nsb.Overhead {
		return nil, errors.Errorf(
			"message is not length of overhead, cannot be valid: %d <= %d",
			len(blob.GetEncData()),
			nsb.Overhead,
		)
	}

	decrypted, ok := nsb.Open(nil, blob.GetEncData(), secretBoxResource.Nonce, secretBoxResource.Key)
	if !ok {
		return nil, errors.New("message did not decrypt with secretbox")
	}

	return decrypted, nil
}

// EncryptBlob encrypts a blob.
// Resolves the resource SecretBoxResource.
func (a *SecretBox) EncryptBlob(ctx context.Context, resolver objectenc.ResourceResolverFunc, data []byte, uncompressedData []byte) (*objectenc.EncryptedBlob, error) {
	blob := &objectenc.EncryptedBlob{EncType: a.GetEncryptionType()}
	resource, err := a.resolveSecretBoxResource(ctx, resolver, blob, data, uncompressedData)
	if err != nil {
		return nil, err
	}

	meta := &SecretBoxMetadata{}
	blob.EncMetadata, err = proto.Marshal(meta)
	if err != nil {
		return nil, err
	}

	blob.EncData = nsb.Seal(nil, data, resource.Nonce, resource.Key)
	return blob, nil
}

func init() {
	objectenc.MustRegisterEncryptionImpl(&SecretBox{})
}
