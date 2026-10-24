package envelope_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"slices"
	"strings"
	"testing"

	"github.com/chrisalmeida/go-mpc/envelope"
	"github.com/stretchr/testify/require"
)

func context() envelope.Context {
	return envelope.Context{Protocol: envelope.FROST, Kind: envelope.Sign1, WireVersion: 1,
		PublicKey: bytes.Repeat([]byte{0x11}, 32), PartyID: 7, Epoch: 9, OperationID: "op", Round: 1}
}

type legacyEncryptor struct {
	aead                 cipher.AEAD
	encrypts, decrypts   int
	inPlace              bool
	plaintext, decrypted []byte
}

func encryptor(t testing.TB) *legacyEncryptor {
	t.Helper()
	// Disposable fixture key. Production key/cipher selection belongs to callers.
	block, err := aes.NewCipher(bytes.Repeat([]byte{0x42}, 32))
	require.NoError(t, err)
	aead, err := cipher.NewGCMWithRandomNonce(block)
	require.NoError(t, err)
	return &legacyEncryptor{aead: aead}
}

func (e *legacyEncryptor) Encrypt(p []byte) ([]byte, error) {
	e.encrypts++
	e.plaintext = p
	var dst []byte
	if e.inPlace {
		dst = p[:0]
	}
	return e.aead.Seal(dst, nil, p, nil), nil
}

func (e *legacyEncryptor) Decrypt(c []byte) ([]byte, error) {
	e.decrypts++
	var dst []byte
	if e.inPlace {
		dst = c[:0]
	}
	p, err := e.aead.Open(dst, nil, c, nil)
	e.decrypted = p
	return p, err
}

type contextEncryptor struct {
	*legacyEncryptor
	sealAAD, openAAD []byte
	seals, opens     int
}

func (e *contextEncryptor) EncryptContext(p, aad []byte) ([]byte, error) {
	e.seals++
	e.sealAAD = slices.Clone(aad)
	return e.aead.Seal(nil, nil, p, aad), nil
}

func (e *contextEncryptor) DecryptContext(c, aad []byte) ([]byte, error) {
	e.opens++
	e.openAAD = slices.Clone(aad)
	return e.aead.Open(nil, nil, c, aad)
}

func headerSize(blob []byte) int { return 3 + int(binary.BigEndian.Uint16(blob[1:3])) }

func assertField(t *testing.T, err error, field string) {
	t.Helper()
	var typed *envelope.Error
	require.ErrorAs(t, err, &typed)
	require.Equal(t, field, typed.Field)
}

func TestRoundTripAllKindsAndEncryptorInterfaces(t *testing.T) {
	t.Parallel()
	for _, protocol := range []string{envelope.DKLS23, envelope.FROST} {
		for _, kind := range []string{envelope.Setup, envelope.Key, envelope.Signer, envelope.Sign1, envelope.Sign2, envelope.Refresh1, envelope.Refresh2, envelope.RefreshOutput, envelope.SignOutput} {
			if (protocol == envelope.DKLS23 && (kind == envelope.Key || kind == envelope.Signer)) ||
				(protocol == envelope.FROST && (kind == envelope.Setup || kind == envelope.Sign2)) {
				continue
			}
			for _, aad := range []bool{false, true} {
				name := protocol + "/" + kind + "/legacy"
				if aad {
					name = protocol + "/" + kind + "/aad"
				}
				t.Run(name, func(t *testing.T) {
					t.Parallel()
					ctx := context()
					ctx.Protocol, ctx.Kind = protocol, kind
					if protocol == envelope.DKLS23 {
						ctx.PublicKey = append(ctx.PublicKey, 0x11)
					}
					switch kind {
					case envelope.Setup, envelope.Key, envelope.Signer:
						ctx.Round, ctx.OperationID = 0, ""
					case envelope.Sign2, envelope.Refresh2, envelope.RefreshOutput, envelope.SignOutput:
						ctx.Round = 2
					}
					var enc envelope.Encryptor = encryptor(t)
					if aad {
						enc = &contextEncryptor{legacyEncryptor: encryptor(t)}
					}
					payload := []byte("disposable private checkpoint")
					blob, err := envelope.Seal(enc, ctx, payload)
					require.NoError(t, err)
					peek, err := envelope.Peek(blob)
					require.NoError(t, err)
					require.Equal(t, ctx, peek)
					peek.PublicKey[0] ^= 1
					got, err := envelope.Open(enc, ctx, blob)
					require.NoError(t, err)
					require.Equal(t, payload, got)
					if bound, ok := enc.(*contextEncryptor); ok {
						require.Equal(t, blob[:headerSize(blob)], bound.sealAAD)
						require.Equal(t, bound.sealAAD, bound.openAAD)
						require.Equal(t, 1, bound.seals)
						require.Equal(t, 1, bound.opens)
						require.Zero(t, bound.encrypts)
						require.Zero(t, bound.decrypts)
					}
				})
			}
		}
	}
}

func TestCanonicalContextEncoding(t *testing.T) {
	t.Parallel()
	enc := encryptor(t)
	blob, err := envelope.Seal(enc, context(), []byte("payload"))
	require.NoError(t, err)
	// Independent byte vector for the specified field order and integer widths.
	want, err := hex.DecodeString("010051" + "000566726f7374" + "00067369676e2d31" +
		"000400000001" + "0020" + strings.Repeat("11", 32) + "000400000007" +
		"00080000000000000009" + "00026f70" + "000400000001")
	require.NoError(t, err)
	require.Equal(t, want, blob[:headerSize(blob)])
}

func TestOpenRejectsEveryContextFieldBeforeDecryption(t *testing.T) {
	t.Parallel()
	enc := encryptor(t)
	ctx := context()
	blob, err := envelope.Seal(enc, ctx, []byte("private"))
	require.NoError(t, err)
	for field, change := range map[string]func(*envelope.Context){
		"protocol":     func(c *envelope.Context) { c.Protocol = envelope.DKLS23; c.PublicKey = append(c.PublicKey, 1) },
		"kind":         func(c *envelope.Context) { c.Kind = envelope.Refresh1 },
		"wire_version": func(c *envelope.Context) { c.WireVersion++ },
		"public_key":   func(c *envelope.Context) { c.PublicKey[0] ^= 1 },
		"party_id":     func(c *envelope.Context) { c.PartyID++ },
		"epoch":        func(c *envelope.Context) { c.Epoch++ },
		"operation_id": func(c *envelope.Context) { c.OperationID = "another longer operation" },
		"round":        func(c *envelope.Context) { c.Round++ },
	} {
		t.Run(field, func(t *testing.T) {
			expect := ctx
			expect.PublicKey = slices.Clone(ctx.PublicKey)
			change(&expect)
			got, err := envelope.Open(enc, expect, blob)
			require.Nil(t, got)
			assertField(t, err, field)
			if field == "round" {
				require.ErrorIs(t, err, envelope.ErrInvalidContext)
			} else {
				require.ErrorIs(t, err, envelope.ErrContextMismatch)
			}
			require.Zero(t, enc.decrypts)
		})
	}
}

func TestSplicedHeaderIsRejectedAfterDecryption(t *testing.T) {
	t.Parallel()
	for _, withAAD := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "aad"}[withAAD], func(t *testing.T) {
			t.Parallel()
			legacy := encryptor(t)
			var enc envelope.Encryptor = legacy
			if withAAD {
				enc = &contextEncryptor{legacyEncryptor: legacy}
			}
			first, second := context(), context()
			second.OperationID = "a different length operation"
			a, err := envelope.Seal(enc, first, []byte("first checkpoint"))
			require.NoError(t, err)
			b, err := envelope.Seal(enc, second, []byte("second checkpoint"))
			require.NoError(t, err)
			spliced := append(slices.Clone(b[:headerSize(b)]), a[headerSize(a):]...)
			peek, err := envelope.Peek(spliced)
			require.NoError(t, err, "Peek is deliberately unauthenticated")
			require.Equal(t, second, peek)
			got, err := envelope.Open(enc, second, spliced)
			require.Nil(t, got)
			if withAAD {
				require.ErrorIs(t, err, envelope.ErrDecrypt)
				require.Equal(t, 1, enc.(*contextEncryptor).opens)
			} else {
				require.ErrorIs(t, err, envelope.ErrContextMismatch)
				assertField(t, err, "operation_id")
				require.Equal(t, 1, legacy.decrypts)
			}
		})
	}
}

func TestTruncationTamperingAndWrongKeyReleaseNoPlaintext(t *testing.T) {
	t.Parallel()
	enc, ctx := encryptor(t), context()
	blob, err := envelope.Seal(enc, ctx, []byte("private"))
	require.NoError(t, err)
	for i := 0; i < len(blob); i++ {
		got, err := envelope.Open(enc, ctx, blob[:i])
		require.Error(t, err, "truncation at %d", i)
		require.Nil(t, got)
	}
	changed := slices.Clone(blob)
	changed[len(changed)-1] ^= 1
	got, err := envelope.Open(enc, ctx, changed)
	require.ErrorIs(t, err, envelope.ErrDecrypt)
	require.Nil(t, got)
	block, err := aes.NewCipher(bytes.Repeat([]byte{0x24}, 32))
	require.NoError(t, err)
	wrong, err := cipher.NewGCMWithRandomNonce(block)
	require.NoError(t, err)
	got, err = envelope.Open(&legacyEncryptor{aead: wrong}, ctx, blob)
	require.ErrorIs(t, err, envelope.ErrDecrypt)
	require.Nil(t, got)
}

func TestRejectsInvalidContextsBeforeEncryptorCalls(t *testing.T) {
	t.Parallel()
	for field, change := range map[string]func(*envelope.Context){
		"protocol":               func(c *envelope.Context) { c.Protocol = "unknown" },
		"kind":                   func(c *envelope.Context) { c.Kind = "unknown" },
		"wire_version":           func(c *envelope.Context) { c.WireVersion = 0 },
		"public_key":             func(c *envelope.Context) { c.PublicKey = c.PublicKey[:31] },
		"party_id":               func(c *envelope.Context) { c.PartyID = 0 },
		"epoch":                  func(c *envelope.Context) { c.Epoch = -1 },
		"operation_id":           func(c *envelope.Context) { c.OperationID = "" },
		"round":                  func(c *envelope.Context) { c.Round = 0 },
		"operation_id oversized": func(c *envelope.Context) { c.OperationID = strings.Repeat("x", math.MaxUint16+1) },
		"context oversized":      func(c *envelope.Context) { c.OperationID = strings.Repeat("x", math.MaxUint16) },
		"frost setup":            func(c *envelope.Context) { c.Kind = envelope.Setup },
		"frost sign-2":           func(c *envelope.Context) { c.Kind = envelope.Sign2; c.Round = 2 },
		"dkls key":               func(c *envelope.Context) { c.Protocol = envelope.DKLS23; c.Kind = envelope.Key },
	} {
		t.Run(field, func(t *testing.T) {
			ctx, enc := context(), encryptor(t)
			change(&ctx)
			got, err := envelope.Seal(enc, ctx, []byte("private"))
			require.ErrorIs(t, err, envelope.ErrInvalidContext)
			require.Nil(t, got)
			got, err = envelope.Open(enc, ctx, nil)
			require.ErrorIs(t, err, envelope.ErrInvalidContext)
			require.Nil(t, got)
			require.Zero(t, enc.encrypts)
			require.Zero(t, enc.decrypts)
		})
	}
	tooLarge := int64(math.MaxInt32) + 1
	for _, party := range []int{-1, int(tooLarge)} {
		ctx := context()
		ctx.PartyID = party
		_, err := envelope.Seal(encryptor(t), ctx, nil)
		require.ErrorIs(t, err, envelope.ErrInvalidContext)
	}
	_, err := envelope.Seal(nil, context(), nil)
	require.ErrorIs(t, err, envelope.ErrInvalidEncryptor)
	_, err = envelope.Open(nil, context(), nil)
	require.ErrorIs(t, err, envelope.ErrInvalidEncryptor)
	assertField(t, err, "encryptor")
}

func TestOwnedBuffersAndInPlaceEncryption(t *testing.T) {
	t.Parallel()
	enc, ctx := encryptor(t), context()
	enc.inPlace = true
	ctx.OperationID = string([]byte{0, 0xff, 'x'})
	payload := []byte("private checkpoint")
	original := slices.Clone(payload)
	blob, err := envelope.Seal(enc, ctx, payload)
	require.NoError(t, err)
	require.Equal(t, original, payload)
	require.Equal(t, make([]byte, len(enc.plaintext)), enc.plaintext)
	before := slices.Clone(blob)
	got, err := envelope.Open(enc, ctx, blob)
	require.NoError(t, err)
	require.Equal(t, original, got)
	require.Equal(t, before, blob)
	require.Equal(t, make([]byte, len(enc.decrypted)), enc.decrypted)
	got[0] ^= 1
	peek, err := envelope.Peek(blob)
	require.NoError(t, err)
	require.Equal(t, ctx, peek)
	peek.PublicKey[0] ^= 1
	require.Equal(t, before, blob)
	empty, err := envelope.Seal(enc, ctx, nil)
	require.NoError(t, err)
	got, err = envelope.Open(enc, ctx, empty)
	require.NoError(t, err)
	require.Empty(t, got)
}

type failingEncryptor struct {
	plaintext, ciphertext []byte
	err                   error
}

func (e *failingEncryptor) Encrypt([]byte) ([]byte, error) { return e.ciphertext, e.err }
func (e *failingEncryptor) Decrypt([]byte) ([]byte, error) { return e.plaintext, e.err }

func TestEncryptorErrorsPreserveCauseAndReleaseNoPlaintext(t *testing.T) {
	t.Parallel()
	cause := errors.New("fixture cipher failure")
	enc := &failingEncryptor{ciphertext: []byte("partial ciphertext"), plaintext: []byte("partial private"), err: cause}
	got, err := envelope.Seal(enc, context(), []byte("private"))
	require.Nil(t, got)
	require.ErrorIs(t, err, envelope.ErrEncrypt)
	require.ErrorIs(t, err, cause)
	require.Equal(t, make([]byte, len(enc.ciphertext)), enc.ciphertext)
	blob, err := envelope.Seal(encryptor(t), context(), []byte("private"))
	require.NoError(t, err)
	got, err = envelope.Open(enc, context(), blob)
	require.Nil(t, got)
	require.ErrorIs(t, err, envelope.ErrDecrypt)
	require.ErrorIs(t, err, cause)
	require.Contains(t, err.Error(), "envelope Open: ciphertext:")
	require.NotContains(t, err.Error(), "partial private")
	require.Equal(t, make([]byte, len(enc.plaintext)), enc.plaintext)
	got, err = envelope.Seal(&failingEncryptor{}, context(), nil)
	require.Nil(t, got)
	require.ErrorIs(t, err, envelope.ErrEncrypt)
}
