package envelope_test

import (
	"bytes"
	"encoding/binary"
	"slices"
	"testing"

	"github.com/chrisalmeida/go-mpc/envelope"
	"github.com/stretchr/testify/require"
)

func fields() [][]byte {
	return [][]byte{[]byte("frost"), []byte("sign-1"), {0, 0, 0, 1}, bytes.Repeat([]byte{0x11}, 32),
		{0, 0, 0, 7}, {0, 0, 0, 0, 0, 0, 0, 9}, []byte("op"), {0, 0, 0, 1}}
}

func rawContext(parts [][]byte) []byte {
	var out []byte
	for _, part := range parts {
		out = binary.BigEndian.AppendUint16(out, uint16(len(part)))
		out = append(out, part...)
	}
	return out
}

func frame(ctx, ciphertext []byte) []byte {
	out := []byte{envelope.FormatVersion, 0, 0}
	binary.BigEndian.PutUint16(out[1:], uint16(len(ctx)))
	return append(append(out, ctx...), ciphertext...)
}

func TestMalformedHeadersAreRejectedBeforeDecryption(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, field string
		blob        []byte
		category    error
	}{
		{"missing header", "header", nil, envelope.ErrInvalidEnvelope},
		{"short header", "header", []byte{1, 0}, envelope.ErrInvalidEnvelope},
		{"unknown format", "format_version", []byte{2, 0, 0}, envelope.ErrUnsupportedVersion},
		{"empty context", "context", []byte{1, 0, 0, 1}, envelope.ErrInvalidEnvelope},
		{"oversized context claim", "context", []byte{1, 255, 255, 1}, envelope.ErrInvalidEnvelope},
		{"context suffix", "context", frame(append(rawContext(fields()), 0), []byte{1}), envelope.ErrInvalidEnvelope},
		{"missing ciphertext", "ciphertext", frame(rawContext(fields()), nil), envelope.ErrInvalidEnvelope},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			enc := encryptor(t)
			before := slices.Clone(tc.blob)
			peek, err := envelope.Peek(tc.blob)
			require.Equal(t, envelope.Context{}, peek)
			require.ErrorIs(t, err, tc.category)
			assertField(t, err, tc.field)
			got, err := envelope.Open(enc, context(), tc.blob)
			require.Nil(t, got)
			require.ErrorIs(t, err, tc.category)
			assertField(t, err, tc.field)
			require.Zero(t, enc.decrypts)
			require.Equal(t, before, tc.blob)
		})
	}
}

func TestRejectsMalformedCanonicalContextFields(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, field string
		index       int
		value       []byte
	}{
		{"unknown protocol", "protocol", 0, []byte("unknown")},
		{"unknown kind", "kind", 1, []byte("unknown")},
		{"zero version", "wire_version", 2, []byte{0, 0, 0, 0}},
		{"short public key", "public_key", 3, make([]byte, 31)},
		{"party zero", "party_id", 4, make([]byte, 4)},
		{"party overflow", "party_id", 4, bytes.Repeat([]byte{255}, 4)},
		{"epoch overflow", "epoch", 5, bytes.Repeat([]byte{255}, 8)},
		{"missing operation", "operation_id", 6, nil},
		{"incorrect round", "round", 7, []byte{0, 0, 0, 2}},
		{"round overflow", "round", 7, bytes.Repeat([]byte{255}, 4)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			parts := fields()
			parts[tc.index] = tc.value
			_, err := envelope.Peek(frame(rawContext(parts), []byte{1}))
			require.ErrorIs(t, err, envelope.ErrInvalidContext)
			assertField(t, err, tc.field)
		})
	}
	for _, i := range []int{2, 4, 5, 7} {
		parts := fields()
		parts[i] = []byte{1}
		_, err := envelope.Peek(frame(rawContext(parts), []byte{1}))
		require.ErrorIs(t, err, envelope.ErrInvalidEnvelope)
	}
	for i, field := range []string{"protocol", "kind", "wire_version", "public_key", "party_id", "epoch", "operation_id", "round"} {
		prefix := rawContext(fields()[:i])
		for _, suffix := range [][]byte{{0}, {0, 2, 1}} {
			_, err := envelope.Peek(frame(append(slices.Clone(prefix), suffix...), []byte{1}))
			require.ErrorIs(t, err, envelope.ErrInvalidEnvelope)
			assertField(t, err, field)
		}
	}
}

func TestInvalidEmbeddedContextsReleaseNoPayload(t *testing.T) {
	t.Parallel()
	for name, invalid := range map[string][]byte{
		"missing context":   nil,
		"incomplete field":  []byte{0, 1},
		"context too large": rawContext([][]byte{make([]byte, 40000), make([]byte, 30000), nil, nil, nil, nil, nil, nil}),
		"wrong round":       rawContext(func() [][]byte { p := fields(); p[7] = []byte{0, 0, 0, 2}; return p }()),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			enc := encryptor(t)
			// Produce an authenticated but malformed inner document directly;
			// header validation alone must not authorize its private payload.
			inner := append(slices.Clone(invalid), []byte("private")...)
			ciphertext := enc.aead.Seal(nil, nil, inner, nil)
			got, err := envelope.Open(enc, context(), frame(rawContext(fields()), ciphertext))
			require.Error(t, err)
			require.Nil(t, got)
		})
	}
}
