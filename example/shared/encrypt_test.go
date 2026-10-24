package shared

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/chrisalmeida/go-mpc/envelope"
	"github.com/stretchr/testify/require"
)

func TestEnvelopeEncryptionAuthenticationAndKeyRotation(t *testing.T) {
	t.Parallel()
	var oldKey, newKey [32]byte
	_, err := rand.Read(oldKey[:])
	require.NoError(t, err)
	_, err = rand.Read(newKey[:])
	require.NoError(t, err)
	old := &AESEncryptor{Key: oldKey, KeyID: "old"}
	new := &AESEncryptor{Key: newKey, KeyID: "new", PreviousKeys: map[string][32]byte{"old": oldKey}}
	context := envelope.Context{Protocol: envelope.FROST, Kind: envelope.Signer, WireVersion: 1, PublicKey: bytes.Repeat([]byte{1}, 32), PartyID: 1}
	plaintext := []byte("disposable test secret")
	blob, err := envelope.Seal(old, context, plaintext)
	require.NoError(t, err)
	recovered, err := envelope.Open(new, context, blob)
	require.NoError(t, err)
	require.Equal(t, plaintext, recovered)
	rotated, err := envelope.Seal(new, context, recovered)
	require.NoError(t, err)
	_, err = envelope.Open(old, context, rotated)
	require.Error(t, err)
	recovered, err = envelope.Open(new, context, rotated)
	require.NoError(t, err)
	require.Equal(t, plaintext, recovered)
	for i := range blob {
		changed := bytes.Clone(blob)
		changed[i] ^= 1
		p, err := envelope.Open(new, context, changed)
		require.Error(t, err)
		require.Empty(t, p)
	}
	for i := range blob {
		p, err := envelope.Open(new, context, blob[:i])
		require.Error(t, err)
		require.Empty(t, p)
	}
	a, err := old.Encrypt(plaintext)
	require.NoError(t, err)
	b, err := old.Encrypt(plaintext)
	require.NoError(t, err)
	require.NotEqual(t, a, b)
	p, err := old.Decrypt(a)
	require.NoError(t, err)
	require.Equal(t, plaintext, p)
	_, err = old.DecryptContext(a, []byte("changed associated data"))
	require.Error(t, err)
}
