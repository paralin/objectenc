package aes

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	"github.com/aperturerobotics/objectenc"
	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
)

// AES is the AES encryption implementation.
type AES struct{}

// GetEncryptionType returns the encryption type this implementation satisfies.
func (a *AES) GetEncryptionType() objectenc.EncryptionType {
	return objectenc.EncryptionType_EncryptionType_AES
}

// ValidateMetadata checks the metadata field.
// If metadata is not expected, this should check that it doesn't exist.
func (a *AES) ValidateMetadata(data []byte) error {
	m, err := parseMetadata(data)
	if err != nil {
		return err
	}

	if err := m.Validate(); err != nil {
		return err
	}

	return nil
}

// resolveCipher resolves the cipher
func (a *AES) resolveCipher(ctx context.Context, resolver objectenc.ResourceResolverFunc, blob *objectenc.EncryptedBlob) (*AESMetadata, cipher.Stream, error) {
	m, err := parseMetadata(blob.GetEncMetadata())
	if err != nil {
		return m, nil, err
	}

	keyResource := &KeyResource{KeySaltMultihash: m, EncryptionType: a.GetEncryptionType()}
	if resolver == nil {
		return m, nil, errors.New("resolver required to lookup aes key")
	}
	// type ResourceResolverFunc func(ctx context.Context, blob *EncryptedBlob, resourceCtr interface{}) error
	if err := resolver(ctx, blob, keyResource); err != nil {
		return m, nil, err
	}

	expectedKeyLen := m.GetKeySize().GetKeyLen()
	if expectedKeyLen != len(keyResource.KeyData) {
		return m, nil, errors.Errorf(
			"retrieved key mh [%s] length %d != expected %d (%s)",
			m.GetKeyMultihash().B58String(),
			len(keyResource.KeyData),
			expectedKeyLen,
			m.GetKeySize().String(),
		)
	}

	blk, err := aes.NewCipher(keyResource.KeyData)
	if err != nil {
		return m, nil, errors.Wrap(err, "build cipher")
	}

	return m, cipher.NewCTR(blk, m.GetIv()), nil
}

// DecryptBlob decrypts an encrypted blob.
// Resolves the resource KeyResource.
func (a *AES) DecryptBlob(ctx context.Context, resolver objectenc.ResourceResolverFunc, blob *objectenc.EncryptedBlob) ([]byte, error) {
	_, stream, err := a.resolveCipher(ctx, resolver, blob)
	if err != nil {
		return nil, err
	}

	plain := make([]byte, len(blob.GetEncData()))
	stream.XORKeyStream(plain, blob.GetEncData())
	return plain, nil
}

// EncryptBlob encrypts a blob.
// Resolves the resource EncryptMetaResource.
func (a *AES) EncryptBlob(ctx context.Context, resolver objectenc.ResourceResolverFunc, data []byte) (*objectenc.EncryptedBlob, error) {
	iv := make([]byte, aesIvLen)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	blob := &objectenc.EncryptedBlob{EncType: a.GetEncryptionType()}
	resource := &EncryptMetaResource{Data: data}
	if resolver == nil {
		return nil, errors.New("resolver required to lookup aes key")
	}
	// type ResourceResolverFunc func(ctx context.Context, blob *EncryptedBlob, resourceCtr interface{}) error
	if err := resolver(ctx, blob, resource); err != nil {
		return nil, err
	}

	ks, err := NewKeySize(len(resource.KeyData))
	if err != nil {
		return nil, err
	}

	mhash := resource.KeyMultihash
	if len(mhash) == 0 {
		mh, err := HashKey(resource.KeyData, &resource.KeyHashSalt, 0)
		if err != nil {
			return nil, err
		}
		mhash = []byte(mh)
		resource.KeyMultihash = mhash
	}

	meta := &AESMetadata{KeySize: ks, KeyHash: mhash, KeyHashSalt: resource.KeyHashSalt, Iv: iv}
	blob.EncMetadata, err = proto.Marshal(meta)
	if err != nil {
		return nil, err
	}

	blk, err := aes.NewCipher(resource.KeyData)
	if err != nil {
		return nil, errors.Wrap(err, "build cipher")
	}
	stream := cipher.NewCTR(blk, iv)

	enc := make([]byte, len(data))
	stream.XORKeyStream(enc, data)
	blob.EncData = enc
	return blob, nil
}

func init() {
	objectenc.MustRegisterEncryptionImpl(&AES{})
}
