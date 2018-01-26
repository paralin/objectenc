# Object Encryption

> Cross-language encryption wrapper for binary blobs.

## Introduction

objectenc is a wrapper for binary blobs with encryption type metadata.

This package also includes cross-platform implementations of each encryption type. Each encryption implementation lives in a sub-package.

Furthermore, compression algorithms are implemented in sub-packages.

## Resource Resolvers

When encrypting and decrypting data, sometimes additional out-of-band information will be required, such as the private or public key for a peer ID or the encryption key.

The code is structured so that this information can be resolved asynchronously.

## Go Implementation

Each sub-package contains an implementation that will be registered globally when the package is initialized. This means that you can selectively compile in encryption types with an import statement like so:

```go
import (
	"github.com/aperturerobotics/objectenc"

    // Register specific algorithms.
	_ "github.com/aperturerobotics/objectenc/blowfish"
	_ "github.com/aperturerobotics/objectenc/aes"
    
    // alternatively, register all algorithms
	_ "github.com/aperturerobotics/objectenc/all"
)
```

