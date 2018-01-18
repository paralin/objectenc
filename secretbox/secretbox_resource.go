package secretbox

// SecretBoxResource requests the key and nonce to use for a secretbox.
type SecretBoxResource struct {
	// Box is set if the box is being opened.
	Box []byte
	// Message is set if the message is being encrypted.
	Message []byte

	// Nonce, set by the resolver.
	Nonce *[24]byte
	// Key, set by the resolver
	Key *[32]byte
}
