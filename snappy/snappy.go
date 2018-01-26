package snappy

import (
	"context"

	"github.com/aperturerobotics/objectenc"
	gs "github.com/golang/snappy"
)

// Snappy is the Snappy compression implementation.
type Snappy struct{}

// GetCompressionType returns the compression type.
func (s *Snappy) GetCompressionType() objectenc.CompressionType {
	return objectenc.CompressionType_CompressionType_SNAPPY
}

// DecompressBlob decompresses a blob.
func (s *Snappy) DecompressBlob(ctx context.Context, data []byte) ([]byte, error) {
	return gs.Decode(nil, data)
}

// CompressBlob compresses a blob.
func (s *Snappy) CompressBlob(ctx context.Context, data []byte) ([]byte, error) {
	return gs.Encode(nil, data), nil
}

func init() {
	objectenc.MustRegisterCompressionImpl(&Snappy{})
}
