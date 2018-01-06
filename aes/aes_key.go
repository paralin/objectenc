package aes

import "errors"

// ErrInvalidKeySize indicates an invalid key size
var ErrInvalidKeySize = errors.New("invalid key size")

var keySizeToKeyLength = map[KeySize]int{
	KeySize_KeySize_AES128: 16,
	KeySize_KeySize_AES192: 24,
	KeySize_KeySize_AES256: 32,
}

var keyLengthToKeySize = map[int]KeySize{
	16: KeySize_KeySize_AES128,
	24: KeySize_KeySize_AES192,
	32: KeySize_KeySize_AES256,
}

// GetKeyLen returns the expected length of the key in bytes.
func (s KeySize) GetKeyLen() int {
	return keySizeToKeyLength[s]
}

// NewKeySize gets the key size for a key length.
func NewKeySize(keyLen int) (KeySize, error) {
	ks, ok := keyLengthToKeySize[keyLen]
	if !ok {
		return KeySize(0), ErrInvalidKeySize
	}
	return ks, nil
}
