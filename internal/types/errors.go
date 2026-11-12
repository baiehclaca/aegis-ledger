package types

import "errors"

// Structural and certificate errors. Callers use errors.Is.
var (
	ErrInvalid   = errors.New("types: invalid value")
	ErrSignature = errors.New("types: signature rejected")
	ErrQuorum    = errors.New("types: quorum not met")
)
