package xpaseto

import (
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"

	"aidanwoods.dev/go-paseto"
)

type key interface {
	ExportHex() string
	ExportBytes() []byte
}

// Key represents a PASETO key for encryption, decryption, signing, or verification.
type Key struct {
	key
	public  key
	version paseto.Version
	purpose paseto.Purpose
	typ     KeyType
}

// NewKey creates a new Key with the specified version, purpose, and underlying key.
// If k is nil, a new key or key pair will be generated.
func NewKey(ver paseto.Version, p paseto.Purpose, k key) (*Key, error) {
	// Sanity check
	if _, err := paseto.NewProtocol(ver, p); err != nil {
		return nil, fmt.Errorf("invalid protocol: %w", err)
	}

	xk := &Key{version: ver, purpose: p, key: k}

	if k == nil {
		keys := newKeys(ver, p)
		xk.key = keys[0]
		xk.public = keys[1]
	}

	xk.typ = keyType(xk.key)

	return xk, nil
}

// LoadKey loads a key from encoded data with the specified version, purpose, and type.
func LoadKey(encData []byte, ver paseto.Version, purpose paseto.Purpose, kt KeyType) (*Key, error) {
	data, err := decodeKeyData(encData)
	if err != nil {
		return nil, fmt.Errorf("failed decoding key data: %w", err)
	}

	k, err := keyFromBytes(data, ver, purpose, kt)
	if err != nil {
		return nil, fmt.Errorf("failed loading key data: %w", err)
	}

	xk := &Key{version: ver, purpose: purpose, typ: kt, key: k}

	return xk, nil
}

// Encrypt encrypts a token using this symmetric key.
func (k Key) Encrypt(token *Token) (string, error) {
	if k.typ != KeyTypeSymmetric {
		return "", errors.New("encrypting only works with symmetric keys")
	}

	var out string
	switch k.version {
	case paseto.Version2:
		out = token.V2Encrypt(k.key.(paseto.V2SymmetricKey))
	case paseto.Version3:
		out = token.V3Encrypt(k.key.(paseto.V3SymmetricKey), nil)
	case paseto.Version4:
		out = token.V4Encrypt(k.key.(paseto.V4SymmetricKey), nil)
	}

	return out, nil
}

// Public returns the public key corresponding to this private key, or nil if
// this is not a private key.
func (k Key) Public() *Key {
	if k.public != nil {
		key, err := NewKey(k.version, k.purpose, k.public)
		if err != nil {
			// This shouldn't happen if the Key was created with NewKey, since
			// k.version, k.purpose, and k.public would've already been validated.
			panic(err)
		}
		return key
	}
	return nil
}

// Render returns the key encoded in the specified format.
func (k Key) Render(enc KeyEncoding) string {
	var s string
	if enc == KeyEncodingHex {
		s = k.ExportHex()
	} else {
		block := &pem.Block{
			Type:  strings.ToUpper(k.typ.Long()),
			Bytes: k.ExportBytes(),
		}
		s = string(pem.EncodeToMemory(block))
	}

	return s
}

// Sign signs a token using this private key.
func (k Key) Sign(token *Token) (string, error) {
	if k.typ != KeyTypePrivate {
		return "", errors.New("signing only works with private keys")
	}

	var out string
	switch k.version {
	case paseto.Version2:
		out = token.V2Sign(k.key.(paseto.V2AsymmetricSecretKey))
	case paseto.Version3:
		out = token.V3Sign(k.key.(paseto.V3AsymmetricSecretKey), nil)
	case paseto.Version4:
		out = token.V4Sign(k.key.(paseto.V4AsymmetricSecretKey), nil)
	}

	return out, nil
}

// Type returns the type of this key.
func (k Key) Type() KeyType {
	return k.typ
}

// Write writes the key to the specified writer in the given encoding format.
// If extra is true, additional information is written for hex keys.
func (k Key) Write(w io.Writer, enc KeyEncoding, extra bool) error {
	out := k.Render(enc)
	if extra && enc == KeyEncodingHex {
		if k.typ == KeyTypeSymmetric {
			out = fmt.Sprintf("%s\n", out)
		} else {
			out = fmt.Sprintf("%s: %s\n", k.typ.Long(), out)
		}
	}

	if _, err := fmt.Fprint(w, out); err != nil {
		return fmt.Errorf("failed writing key: %w", err)
	}

	return nil
}

func newKeys(ver paseto.Version, purpose paseto.Purpose) [2]key {
	var privKey, pubKey key
	switch ver {
	case paseto.Version2:
		if purpose == paseto.Local {
			privKey = paseto.NewV2SymmetricKey()
		} else {
			k := paseto.NewV2AsymmetricSecretKey()
			privKey = k
			pubKey = k.Public()
		}
	case paseto.Version3:
		if purpose == paseto.Local {
			privKey = paseto.NewV3SymmetricKey()
		} else {
			k := paseto.NewV3AsymmetricSecretKey()
			privKey = k
			pubKey = k.Public()
		}
	case paseto.Version4:
		if purpose == paseto.Local {
			privKey = paseto.NewV4SymmetricKey()
		} else {
			k := paseto.NewV4AsymmetricSecretKey()
			privKey = k
			pubKey = k.Public()
		}
	}

	return [2]key{privKey, pubKey}
}

// KeyType represents the type of cryptographic key.
type KeyType string

const (
	KeyTypePrivate   KeyType = "private"
	KeyTypePublic    KeyType = "public"
	KeyTypeSymmetric KeyType = "symmetric"
)

// Short returns a shortened representation of the key type.
func (kt KeyType) Short() string {
	switch kt {
	case KeyTypePrivate:
		return "priv"
	case KeyTypePublic:
		return "pub"
	case KeyTypeSymmetric:
		return "sym"
	}
	return ""
}

// Long returns a human-readable description of the key type.
func (kt KeyType) Long() string {
	if kt.Short() == "" {
		return ""
	}
	// strings.Title is deprecated, and I don't want to add another dependency for this
	return fmt.Sprintf("%s%s key", strings.ToUpper(string(kt[0])), kt[1:])
}

// KeyEncoding represents the encoding format for keys.
type KeyEncoding string

const (
	KeyEncodingHex KeyEncoding = "hex"
	KeyEncodingPEM KeyEncoding = "pem"
)

func keyType(key any) KeyType {
	switch key.(type) {
	case paseto.V2SymmetricKey, paseto.V3SymmetricKey, paseto.V4SymmetricKey:
		return KeyTypeSymmetric
	case paseto.V2AsymmetricSecretKey, paseto.V3AsymmetricSecretKey, paseto.V4AsymmetricSecretKey:
		return KeyTypePrivate
	case paseto.V2AsymmetricPublicKey, paseto.V3AsymmetricPublicKey, paseto.V4AsymmetricPublicKey:
		return KeyTypePublic
	default:
		panic(fmt.Sprintf("invalid key type: %T", key))
	}
}

func decodeKeyData(encData []byte) ([]byte, error) {
	keyBlock, _ := pem.Decode(encData)
	if keyBlock != nil {
		return keyBlock.Bytes, nil
	}

	dst := make([]byte, hex.DecodedLen(len(encData)))
	_, err := hex.Decode(dst, encData)
	if err != nil {
		return nil, fmt.Errorf("failed decoding hex data: %w", err)
	}

	return dst, nil
}

func keyFromBytes(data []byte, ver paseto.Version, purpose paseto.Purpose, kt KeyType) (k key, err error) {
	switch ver {
	case paseto.Version2:
		if purpose == paseto.Local {
			k, err = paseto.V2SymmetricKeyFromBytes(data)
		} else {
			if kt == KeyTypePrivate {
				k, err = paseto.NewV2AsymmetricSecretKeyFromBytes(data)
			} else {
				k, err = paseto.NewV2AsymmetricPublicKeyFromBytes(data)
			}
		}
	case paseto.Version3:
		if purpose == paseto.Local {
			k, err = paseto.V3SymmetricKeyFromBytes(data)
		} else {
			if kt == KeyTypePrivate {
				k, err = paseto.NewV3AsymmetricSecretKeyFromBytes(data)
			} else {
				k, err = paseto.NewV3AsymmetricPublicKeyFromBytes(data)
			}
		}
	case paseto.Version4:
		if purpose == paseto.Local {
			k, err = paseto.V4SymmetricKeyFromBytes(data)
		} else {
			if kt == KeyTypePrivate {
				k, err = paseto.NewV4AsymmetricSecretKeyFromBytes(data)
			} else {
				k, err = paseto.NewV4AsymmetricPublicKeyFromBytes(data)
			}
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed reading key data: %w", err)
	}

	return k, nil
}
