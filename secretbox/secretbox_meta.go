package secretbox

import (
	// 	"crypto/aes"
	"github.com/golang/protobuf/proto"
)

// aesIvLen is the length in bytes of the IV.
const aesIvLen = 16

// parseMetadata parses metadata.
func parseMetadata(data []byte) (*SecretBoxMetadata, error) {
	m := &SecretBoxMetadata{}
	if err := proto.Unmarshal(data, m); err != nil {
		return nil, err
	}
	return m, nil
}

// Validate checks the metadata.
func (m *SecretBoxMetadata) Validate() error {
	return nil
}
