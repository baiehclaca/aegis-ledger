// Package p2p is the validator transport. Frames are length-prefixed.
// The handshake is TLS 1.3 with the X25519MLKEM768 hybrid and an
// ML-DSA-65 certificate. A peer is accepted only when that certificate's
// key is in the validator set. There is no external CA.
package p2p
