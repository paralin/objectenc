package aes

import (
	// 	"crypto/aes"
	"github.com/golang/protobuf/proto"
	"github.com/multiformats/go-multihash"
	"github.com/pkg/errors"
)

// aesIvLen is the length in bytes of the IV.
const aesIvLen = 16

// parseMetadata parses metadata.
func parseMetadata(data []byte) (*AESMetadata, error) {
	m := &AESMetadata{}
	if err := proto.Unmarshal(data, m); err != nil {
		return nil, err
	}
	return m, nil
}

// Validate checks the metadata.
func (m *AESMetadata) Validate() error {
	if _, ok := KeySize_name[int32(m.KeySize)]; !ok {
		return errors.Errorf("key size unknown: %s", m.KeySize.String())
	}
	_, err := multihash.Cast(m.GetKeyHash())
	if err != nil {
		return err
	}
	if len(m.GetIv()) != aesIvLen {
		return errors.Errorf("expected iv length %d != actual %d", aesIvLen, len(m.GetIv()))
	}
	if len(m.GetKeyHashSalt()) != KeyHashSaltLen {
		return errors.Errorf("expected key hash salt length %d != actual %d", KeyHashSaltLen, len(m.GetKeyHashSalt()))
	}
	return nil
}

// GetKeyMultihash returns the key multihash of the object.
func (m *AESMetadata) GetKeyMultihash() multihash.Multihash {
	// expected to be validated with Validate() before
	mh, _ := multihash.Cast(m.GetKeyHash())
	return mh
}

// GetKeyMultihashSalt returns the key multihash salt.
func (m *AESMetadata) GetKeyMultihashSalt() []byte {
	return m.GetKeyHashSalt()
}
