// Package envelope binds caller-encrypted private state to its public context.
// Its versioned container implements section 1 of
// docs/encrypted-state-and-cold-signing.md; it adds no cryptographic transcript.
// Cipher selection, authenticated encryption, keys and rollback protection
// remain the caller's responsibilities. Peek returns unauthenticated metadata.
package envelope

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
)

// FormatVersion identifies this container format, independently of the payload's
// WireVersion. Existing protocol serialization formats are unaffected.
const FormatVersion byte = 1

// Encryptor supplies authenticated encryption without requiring associated-data
// support. Decrypt must reject modified ciphertext. Encryption alone, such as an
// unauthenticated stream cipher, cannot establish the envelope's integrity.
// Calls receive owned buffers and may operate in place. Returned buffers belong
// to the caller and may be cleared after use. Implementations manage their own
// encryption keys and fresh cipher nonces; the envelope chooses neither.
type Encryptor interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

// ContextEncryptor optionally authenticates the complete clear header as
// associated data, in addition to the encrypted context copy. When implemented,
// these methods are used instead of Encrypt and Decrypt. See crypto/cipher.AEAD's
// Seal/Open contract: https://pkg.go.dev/crypto/cipher#AEAD.
type ContextEncryptor interface {
	Encryptor
	EncryptContext(plaintext, associatedData []byte) ([]byte, error)
	DecryptContext(ciphertext, associatedData []byte) ([]byte, error)
}

var (
	ErrInvalidContext     = errors.New("invalid context")
	ErrInvalidEnvelope    = errors.New("invalid envelope")
	ErrUnsupportedVersion = errors.New("unsupported envelope version")
	ErrContextMismatch    = errors.New("context mismatch")
	ErrInvalidEncryptor   = errors.New("encryptor is required")
	ErrEncrypt            = errors.New("encryption failed")
	ErrDecrypt            = errors.New("decryption failed")
)

// Error identifies a failed operation and public context/header field, without
// including field values or private payload bytes. Unwrap supports errors.Is
// and errors.As, including underlying encryptor errors.
type Error struct {
	Op    string
	Field string
	Err   error
}

func (e *Error) Error() string { return fmt.Sprintf("envelope %s: %s: %v", e.Op, e.Field, e.Err) }
func (e *Error) Unwrap() error { return e.Err }

func failure(op, field string, err error) error { return &Error{Op: op, Field: field, Err: err} }

// Seal encodes version || uint16(context length) || context || ciphertext.
// Ciphertext encrypts context || plaintext. ContextEncryptor receives the whole
// clear header as associated data. All caller inputs are preserved, including
// with an encryptor that works in place. Temporary plaintext is cleared on exit;
// Go may retain other copies, so this is not a physical memory-erasure guarantee.
func Seal(enc Encryptor, ctx Context, plaintext []byte) ([]byte, error) {
	if enc == nil {
		return nil, failure("Seal", "encryptor", ErrInvalidEncryptor)
	}
	encoded, err := encodeContext(ctx, "Seal")
	if err != nil {
		return nil, err
	}
	header := []byte{FormatVersion, 0, 0}
	binary.BigEndian.PutUint16(header[1:], uint16(len(encoded)))
	header = append(header, encoded...)
	inner := append(slices.Clone(encoded), plaintext...)
	defer clear(inner)
	var ciphertext []byte
	if bound, ok := enc.(ContextEncryptor); ok {
		ciphertext, err = bound.EncryptContext(inner, slices.Clone(header))
	} else {
		ciphertext, err = enc.Encrypt(inner)
	}
	if err != nil {
		clear(ciphertext)
		return nil, failure("Seal", "ciphertext", fmt.Errorf("%w: %w", ErrEncrypt, err))
	}
	if len(ciphertext) == 0 {
		return nil, failure("Seal", "ciphertext", ErrEncrypt)
	}
	return append(header, ciphertext...), nil
}

// Open checks the clear context against expect before decryption, then checks
// the decrypted context before returning an owned payload. No failure returns
// plaintext. Both comparisons use crypto/subtle.ConstantTimeCompare, whose
// Go 1.26.1 implementation compares equal-length slices without data-dependent
// exits (crypto/internal/fips140/subtle/constant_time.go). Context lengths and
// mismatch field names are public. Encryptor must authenticate ciphertext.
func Open(enc Encryptor, expect Context, blob []byte) ([]byte, error) {
	if enc == nil {
		return nil, failure("Open", "encryptor", ErrInvalidEncryptor)
	}
	want, err := encodeContext(expect, "Open")
	if err != nil {
		return nil, err
	}
	_, encoded, header, ciphertext, err := parse(blob, "Open")
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(encoded, want) != 1 {
		return nil, failure("Open", mismatchField(encoded, want), ErrContextMismatch)
	}
	input := slices.Clone(ciphertext)
	defer clear(input)
	var plaintext []byte
	if bound, ok := enc.(ContextEncryptor); ok {
		plaintext, err = bound.DecryptContext(input, slices.Clone(header))
	} else {
		plaintext, err = enc.Decrypt(input)
	}
	defer clear(plaintext)
	if err != nil {
		return nil, failure("Open", "ciphertext", fmt.Errorf("%w: %w", ErrDecrypt, err))
	}
	// Use the trusted expected length and field boundaries. Do not interpret
	// decrypted length prefixes before the embedded copy has matched.
	if len(plaintext) < len(want) || subtle.ConstantTimeCompare(plaintext[:len(want)], want) != 1 {
		return nil, failure("Open", mismatchField(plaintext, want), ErrContextMismatch)
	}
	return slices.Clone(plaintext[len(want):]), nil
}

// Peek validates the container framing and context shape without decrypting or
// authenticating anything. The returned PublicKey is owned. Use independently
// trusted records to select Open's expected context, rather than trusting Peek.
func Peek(blob []byte) (Context, error) {
	ctx, _, _, _, err := parse(blob, "Peek")
	return ctx, err
}

func parse(blob []byte, op string) (Context, []byte, []byte, []byte, error) {
	if len(blob) < 3 {
		return Context{}, nil, nil, nil, failure(op, "header", ErrInvalidEnvelope)
	}
	if blob[0] != FormatVersion {
		return Context{}, nil, nil, nil, failure(op, "format_version", ErrUnsupportedVersion)
	}
	n := int(binary.BigEndian.Uint16(blob[1:3]))
	if n == 0 || n > len(blob)-3 {
		return Context{}, nil, nil, nil, failure(op, "context", ErrInvalidEnvelope)
	}
	encoded := blob[3 : 3+n]
	ctx, consumed, err := decodeContext(encoded, op)
	if err != nil {
		return Context{}, nil, nil, nil, err
	}
	if consumed != n {
		return Context{}, nil, nil, nil, failure(op, "context", ErrInvalidEnvelope)
	}
	if len(blob) == 3+n {
		return Context{}, nil, nil, nil, failure(op, "ciphertext", ErrInvalidEnvelope)
	}
	return ctx, encoded, blob[:3+n], blob[3+n:], nil
}

func mismatchField(a, b []byte) string {
	for _, field := range contextFields {
		n := 2 + int(binary.BigEndian.Uint16(b))
		if len(a) < n || subtle.ConstantTimeCompare(a[:n], b[:n]) != 1 {
			return field
		}
		a, b = a[n:], b[n:]
	}
	return "context"
}
