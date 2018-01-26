package objectenc

import (
	"context"
)

// PassthroughCompression is the pass-through compression implementation.
type PassthroughCompression struct{}

// GetCompressionType returns the encryption type this implementation satisfies.
func (p *PassthroughCompression) GetCompressionType() CompressionType {
	return CompressionType_CompressionType_UNCOMPRESSED
}

// CompressBlob compresses a blob.
func (p *PassthroughCompression) CompressBlob(_ context.Context, data []byte) ([]byte, error) {
	d := make([]byte, len(data))
	copy(d, data)
	return d, nil
}

// DecompressBlob de-compresses a blob.
func (p *PassthroughCompression) DecompressBlob(_ context.Context, data []byte) ([]byte, error) {
	d := make([]byte, len(data))
	copy(d, data)
	return d, nil
}

func init() {
	MustRegisterCompressionImpl(&PassthroughCompression{})
}
