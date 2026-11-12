// Package codec is the canonical binary encoding for Silver Grey Ledger.
//
// Every integer field is big-endian and fixed width, so a value has one
// encoding. Lengths and list counts use the DER definite form, and a
// non-minimal length is rejected: that is the only width that varies, and
// the shortest form is the only legal one. The encoding has no optional
// fields, no maps, and no floats. Field order is the order in the spec.
//
// Decoders reject trailing bytes, unknown versions, and oversize fields.
// A value that decodes must encode back to the same bytes. Network and
// file input enters the process only through these decoders.
package codec
