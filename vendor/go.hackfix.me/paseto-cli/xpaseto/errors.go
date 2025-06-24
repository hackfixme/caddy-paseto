package xpaseto

import "errors"

// ErrKeyTokenProtocolMismatch indicates that the token's version and purpose
// don't match the key's.
var ErrKeyTokenProtocolMismatch = errors.New("token's version and purpose doesn't match the key's")
