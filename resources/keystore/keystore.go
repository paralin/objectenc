package keystore

import (
	"hash/crc32"
	"sync"

	"github.com/aperturerobotics/objectenc/resources"
	"github.com/hashicorp/golang-lru"
	"github.com/multiformats/go-multihash"
)

// KeyResourceStore stores key resources.
type KeyResourceStore struct {
	keyMap             sync.Map           // map[uint32][]byte
	keyPrefixHashCache *lru.TwoQueueCache // map[uint32][]byte
}

// NewKeyResourceStore builds a new KeyResourceStore.
func NewKeyResourceStore() *KeyResourceStore {
	lrun, err := lru.New2Q(84)
	if err != nil {
		panic(err) // should never happen
	}
	return &KeyResourceStore{
		keyPrefixHashCache: lrun,
	}
}

// AddKey adds an encryption key to the store.
func (s *KeyResourceStore) AddKey(key []byte) {
	crc := crc32.ChecksumIEEE(key)
	s.keyMap.Store(crc, key)
}

// GetByMultihash gets by multihash and returns the key and ok.
func (s *KeyResourceStore) GetByMultihash(ksm resources.KeySaltMultihash) ([]byte, bool) {
	keyMultiHash, err := multihash.Decode(ksm.GetKeyMultihash())
	if err != nil {
		return nil, false
	}

	mhCode := keyMultiHash.Code

	salt := ksm.GetKeyMultihashSalt()
	mhashDat := []byte(ksm.GetKeyMultihash())
	mhashCrc := crc32.ChecksumIEEE(mhashDat)

	keyInter, found := s.keyPrefixHashCache.Get(mhashCrc)
	if found {
		return keyInter.([]byte), true
	}

	var sumErr error
	var foundKey []byte
	s.keyMap.Range(func(_ interface{}, value interface{}) bool {
		key := value.([]byte)
		keyWithSaltPrefix := make([]byte, len(salt)+len(key))
		copy(keyWithSaltPrefix, salt)
		copy(keyWithSaltPrefix[len(salt):], key)
		keyMh, err := multihash.Sum(keyWithSaltPrefix, mhCode, keyMultiHash.Length)
		if err != nil {
			sumErr = err
			return false
		}
		keyMhCrc := crc32.ChecksumIEEE(keyMh)
		s.keyPrefixHashCache.Add(keyMhCrc, key)

		if keyMhCrc != mhashCrc {
			return true
		}

		foundKey = key
		return false
	})

	if sumErr != nil {
		return nil, false
	}

	return foundKey, foundKey != nil
}
