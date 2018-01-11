package aes

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	"github.com/aperturerobotics/objectenc"
	"github.com/golang/protobuf/proto"
	"github.com/multiformats/go-multihash"
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
func (a *AES) resolveCipher(
	ctx context.Context,
	resolver objectenc.ResourceResolverFunc,
	blob *objectenc.EncryptedBlob,
	iv []byte,
	encryptDat []byte,
	keySaltMultihash KeySaltMultihash,
) (*KeyResource, cipher.Stream, error) {
	if resolver == nil {
		return nil, nil, errors.New("resolver required to lookup aes key")
	}

	keyResource := &KeyResource{KeySaltMultihash: keySaltMultihash, EncryptionType: a.GetEncryptionType()}
	if encryptDat != nil {
		keyResource.Encrypting = true
		keyResource.EncryptingData = encryptDat
	}

	if err := resolver(ctx, blob, keyResource); err != nil {
		return keyResource, nil, err
	}

	blk, err := aes.NewCipher(keyResource.KeyData)
	if err != nil {
		return keyResource, nil, errors.Wrap(err, "build cipher")
	}

	return keyResource, cipher.NewCTR(blk, iv), nil
}

// DecryptBlob decrypts an encrypted blob.
// Resolves the resource KeyResource.
func (a *AES) DecryptBlob(ctx context.Context, resolver objectenc.ResourceResolverFunc, blob *objectenc.EncryptedBlob) ([]byte, error) {
	m, err := parseMetadata(blob.GetEncMetadata())
	if err != nil {
		return nil, err
	}

	keyResource, stream, err := a.resolveCipher(ctx, resolver, blob, m.GetIv(), nil, m)
	if err != nil {
		return nil, err
	}

	expectedKeyLen := m.GetKeySize().GetKeyLen()
	if expectedKeyLen != len(keyResource.KeyData) {
		return nil, errors.Errorf(
			"retrieved key mh [%s] length %d != expected %d (%s)",
			m.GetKeyMultihash().B58String(),
			len(keyResource.KeyData),
			expectedKeyLen,
			m.GetKeySize().String(),
		)
	}

	plain := make([]byte, len(blob.GetEncData()))
	stream.XORKeyStream(plain, blob.GetEncData())
	return plain, nil
}

type keyMultihashWithSalt struct {
	mh         multihash.Multihash
	saltPrefix []byte
}

// GetKeyMultihash returns the key multihash or nil of it is invalid.
func (k *keyMultihashWithSalt) GetKeyMultihash() multihash.Multihash {
	return k.mh
}

// GetKeyMultihashSalt returns the key multihash salt.
func (k *keyMultihashWithSalt) GetKeyMultihashSalt() []byte {
	return k.saltPrefix
}

// EncryptBlob encrypts a blob.
// Resolves the resource EncryptMetaResource.
func (a *AES) EncryptBlob(ctx context.Context, resolver objectenc.ResourceResolverFunc, data []byte) (*objectenc.EncryptedBlob, error) {
	iv := make([]byte, aesIvLen)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	blob := &objectenc.EncryptedBlob{EncType: a.GetEncryptionType()}
	resource, stream, err := a.resolveCipher(ctx, resolver, blob, iv, data, nil)
	if err != nil {
		return nil, err
	}

	ks, err := NewKeySize(len(resource.KeyData))
	if err != nil {
		return nil, err
	}

	mhash := resource.KeySaltMultihash
	if mhash == nil {
		var saltPrefix []byte
		mh, err := HashKey(resource.KeyData, &saltPrefix, 0)
		if err != nil {
			return nil, err
		}

		resource.KeySaltMultihash = &keyMultihashWithSalt{mh: mh, saltPrefix: saltPrefix}
		mhash = resource.KeySaltMultihash
	}

	meta := &AESMetadata{KeySize: ks, KeyHash: mhash.GetKeyMultihash(), KeyHashSalt: mhash.GetKeyMultihashSalt(), Iv: iv}
	blob.EncMetadata, err = proto.Marshal(meta)
	if err != nil {
		return nil, err
	}

	enc := make([]byte, len(data))
	stream.XORKeyStream(enc, data)
	blob.EncData = enc
	return blob, nil
}

func init() {
	objectenc.MustRegisterEncryptionImpl(&AES{})
}
