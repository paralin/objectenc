package secretbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	mrand "math/rand"
	"testing"

	"github.com/aperturerobotics/objectenc"
)

// TestAESEncrypt tests encrypting with AES.
func TestAESEncrypt(t *testing.T) {
	ctx := context.Background()
	data := make([]byte, 1000) // 1kb of random data
	mrand.Read(data)

	secretKeyBytes, err := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	if err != nil {
		panic(err)
	}

	var secretKey [32]byte
	copy(secretKey[:], secretKeyBytes)

	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic(err)
	}

	var keyNonceResolver objectenc.ResourceResolverFunc = func(
		ctx context.Context,
		blob *objectenc.EncryptedBlob,
		resourceCtr interface{},
	) error {
		resource := resourceCtr.(*SecretBoxResource)
		resource.Key = &secretKey
		resource.Nonce = &nonce
		return nil
	}

	blob, err := objectenc.EncryptWithResolver(ctx, keyNonceResolver, objectenc.EncryptionType_EncryptionType_SECRET_BOX, data)
	if err != nil {
		t.Fatal(err.Error())
	}

	if err := blob.Validate(); err != nil {
		t.Fatal(err.Error())
	}

	decData, err := blob.DecryptWithResolver(ctx, keyNonceResolver)
	if err != nil {
		t.Fatal(err.Error())
	}

	if bytes.Compare(decData, data) != 0 {
		t.Fatal("decrypted data does not match source data")
	}
}
