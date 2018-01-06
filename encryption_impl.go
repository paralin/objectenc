package objectenc

import (
	"context"
	"sync"

	"github.com/pkg/errors"
)

// ErrDuplicateImpl is returned when a duplicate encryption implementation is registered.
var ErrDuplicateImpl = errors.New("duplicate encryption implementation")

// EncryptionImpl is an implementation of a encryption type.
type EncryptionImpl interface {
	// GetEncryptionType returns the encryption type this implementation satisfies.
	GetEncryptionType() EncryptionType
	// ValidateMetadata checks the metadata field.
	// If metadata is not expected, this should check that it doesn't exist.
	ValidateMetadata([]byte) error
	// DecryptBlob decrypts an encrypted blob.
	DecryptBlob(context.Context, ResourceResolverFunc, *EncryptedBlob) ([]byte, error)
	// EncryptBlob encrypts a blob.
	EncryptBlob(context.Context, ResourceResolverFunc, []byte) (*EncryptedBlob, error)
}

// encryptionImplsMtx is the mutex on the encryptionImpls map
var encryptionImplsMtx sync.RWMutex

// encryptionImpls contains registered implementations.
var encryptionImpls = make(map[EncryptionType]EncryptionImpl)

// MustRegisterEncryptionImpl registers an encryption implementation or panics.
// expected to be called from Init(), but can be deferred
func MustRegisterEncryptionImpl(impl EncryptionImpl) {
	if err := RegisterEncryptionImpl(impl); err != nil {
		panic(err)
	}
}

// RegisterEncryptionImpl registers an encryption implementation.
// expected to be called from Init(), but can be deferred
func RegisterEncryptionImpl(impl EncryptionImpl) error {
	encType := impl.GetEncryptionType()

	encryptionImplsMtx.Lock()
	defer encryptionImplsMtx.Unlock()

	if _, ok := encryptionImpls[encType]; ok {
		return ErrDuplicateImpl
	}

	encryptionImpls[encType] = impl
	return nil
}

// GetEncryptionImpl returns the registered implementation of the type.
func GetEncryptionImpl(kind EncryptionType) (impl EncryptionImpl, err error) {
	if _, ok := EncryptionType_name[int32(kind)]; !ok {
		return nil, errors.Errorf("encryption type unknown: %v", kind.String())
	}

	encryptionImplsMtx.RLock()
	impl = encryptionImpls[kind]
	encryptionImplsMtx.RUnlock()

	if impl == nil {
		err = errors.Errorf("unimplemented encryption type: %v", kind.String())
	}
	return
}
