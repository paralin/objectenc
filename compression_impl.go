package objectenc

import (
	"context"
	"sync"

	"github.com/pkg/errors"
)

// CompressionImpl is an implementation of a compression type.
type CompressionImpl interface {
	// GetCompressionType returns the compression type this implementation satisfies.
	GetCompressionType() CompressionType
	// DecompressBlob decompresses a blob.
	DecompressBlob(context.Context, []byte) ([]byte, error)
	// CompressBlob compresses a blob.
	CompressBlob(context.Context, []byte) ([]byte, error)
}

// compressionImplsMtx is the mutex on the compressionImpls map
var compressionImplsMtx sync.RWMutex

// compressionImpls contains registered implementations.
var compressionImpls = make(map[CompressionType]CompressionImpl)

// MustRegisterCompressionImpl registers an encryption implementation or panics.
// expected to be called from Init(), but can be deferred
func MustRegisterCompressionImpl(impl CompressionImpl) {
	if err := RegisterCompressionImpl(impl); err != nil {
		panic(err)
	}
}

// RegisterCompressionImpl registers an encryption implementation.
// expected to be called from Init(), but can be deferred
func RegisterCompressionImpl(impl CompressionImpl) error {
	encType := impl.GetCompressionType()

	compressionImplsMtx.Lock()
	defer compressionImplsMtx.Unlock()

	if _, ok := compressionImpls[encType]; ok {
		return ErrDuplicateImpl
	}

	compressionImpls[encType] = impl
	return nil
}

// GetCompressionImpl returns the registered implementation of the type.
func GetCompressionImpl(kind CompressionType) (impl CompressionImpl, err error) {
	if _, ok := CompressionType_name[int32(kind)]; !ok {
		return nil, errors.Errorf("encryption type unknown: %v", kind.String())
	}

	compressionImplsMtx.RLock()
	impl = compressionImpls[kind]
	compressionImplsMtx.RUnlock()

	if impl == nil {
		err = errors.Errorf("unimplemented encryption type: %v", kind.String())
	}
	return
}
