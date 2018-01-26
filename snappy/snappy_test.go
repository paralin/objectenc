package snappy

import (
	"bytes"
	"context"
	mrand "math/rand"
	"testing"

	"github.com/aperturerobotics/objectenc"
)

// TestSnappyEncrypt tests encrypting with Snappy
func TestSnappyEncrypt(t *testing.T) {
	ctx := context.Background()
	data := make([]byte, 1000) // 1kb of random data
	mrand.Read(data)

	blob, err := objectenc.Encrypt(objectenc.EncryptionType_EncryptionType_UNENCRYPTED, objectenc.CompressionType_CompressionType_SNAPPY, data)
	if err != nil {
		t.Fatal(err.Error())
	}

	if err := blob.Validate(); err != nil {
		t.Fatal(err.Error())
	}

	decData, err := blob.Decrypt(ctx)
	if err != nil {
		t.Fatal(err.Error())
	}

	if bytes.Compare(decData, data) != 0 {
		t.Fatal("decrypted data does not match source data")
	}
}
