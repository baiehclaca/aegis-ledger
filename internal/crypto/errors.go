package crypto

import "errors"

// Callers use errors.Is. The text names the failure and not the key bytes.
var (
	ErrKey       = errors.New("crypto: invalid key")
	ErrContext   = errors.New("crypto: invalid context")
	ErrSignature = errors.New("crypto: signature rejected")
	ErrAlgorithm = errors.New("crypto: unsupported algorithm")
)
