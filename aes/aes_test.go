package aes

import (
	"bytes"
	"context"
	mrand "math/rand"
	"testing"

	"github.com/aperturerobotics/objectenc"
)

// TestAESEncrypt tests encrypting with AES.
func TestAESEncrypt(t *testing.T) {
	ctx := context.Background()
	data := make([]byte, 1000) // 1kb of random data
	mrand.Read(data)

	key := make([]byte, KeySize_KeySize_AES256.GetKeyLen())
	mrand.Read(key)

	var encryptResolver objectenc.ResourceResolverFunc = func(
		ctx context.Context,
		blob *objectenc.EncryptedBlob,
		resourceCtr interface{},
	) error {
		resource := resourceCtr.(*EncryptMetaResource)
		resource.KeyData = key
		return nil
	}

	blob, err := objectenc.EncryptWithResolver(ctx, encryptResolver, objectenc.EncryptionType_EncryptionType_AES, data)
	if err != nil {
		t.Fatal(err.Error())
	}

	if err := blob.Validate(); err != nil {
		t.Fatal(err.Error())
	}

	var decryptResolver objectenc.ResourceResolverFunc = func(
		ctx context.Context,
		blob *objectenc.EncryptedBlob,
		resourceCtr interface{},
	) error {
		resource := resourceCtr.(*KeyResource)
		resource.KeyData = key
		return nil
	}

	decData, err := blob.DecryptWithResolver(ctx, decryptResolver)
	if err != nil {
		t.Fatal(err.Error())
	}

	if bytes.Compare(decData, data) != 0 {
		t.Fatal("decrypted data does not match source data")
	}
}
