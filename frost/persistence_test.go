package frost

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarshalUnmarshalKeyShare(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	ks := keyShares[1]

	data, err := MarshalKeyShare(ks)
	require.NoError(t, err)

	got, err := UnmarshalKeyShare(data)
	require.NoError(t, err)
	assert.Equal(t, ks.ID, got.ID)
	assert.Equal(t, ks.SecretShare, got.SecretShare)
	assert.Equal(t, ks.PublicKey, got.PublicKey)
}

func TestMarshalUnmarshalSignerState(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	ss := NewSignerState(keyShares[1])
	ss.Blacklist[3] = true

	data, err := MarshalSignerState(ss)
	require.NoError(t, err)

	got, err := UnmarshalSignerState(data)
	require.NoError(t, err)
	assert.Equal(t, keyShares[1].ID, got.KeyShare.ID)
	assert.True(t, got.Blacklist[3])
}

func TestEncryptedRoundTrip(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	ks := keyShares[1]

	enc := &identityEncryptor{}
	ct, err := MarshalEncrypted(ks, enc)
	require.NoError(t, err)

	got, err := UnmarshalEncrypted(ct, enc, ks.Binding())
	require.NoError(t, err)
	assert.Equal(t, ks.ID, got.ID)
	assert.Equal(t, ks.SecretShare, got.SecretShare)
}

func TestEncryptedErrors(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)

	enc := &failingEncryptor{}
	_, err := MarshalEncrypted(keyShares[1], enc)
	assert.Error(t, err)

	_, err = UnmarshalEncrypted([]byte("garbage"), enc, keyShares[1].Binding())
	assert.Error(t, err)
}

func TestUnmarshalKeyShareInvalid(t *testing.T) {
	t.Parallel()
	_, err := UnmarshalKeyShare([]byte("not json"))
	assert.Error(t, err)
}

func TestUnmarshalSignerStateInvalid(t *testing.T) {
	t.Parallel()
	_, err := UnmarshalSignerState([]byte("not json"))
	assert.Error(t, err)
}

func TestEncryptedRoundTripFunctional(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	msg := []byte("encrypt round-trip functional test")

	enc := &identityEncryptor{}

	// Encrypt, decrypt, then sign with restored shares.
	restored := make(map[int]*KeyShare)
	for id, ks := range keyShares {
		ct, err := MarshalEncrypted(ks, enc)
		require.NoError(t, err)
		got, err := UnmarshalEncrypted(ct, enc, ks.Binding())
		require.NoError(t, err)
		restored[id] = got
	}

	sig := fullSign(t, restored, []int{1, 2, 3}, msg)
	assert.True(t, Verify(restored[1].PublicKey, msg, sig))
}

func TestSignerStateRoundTripFunctional(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	msg := []byte("signer state round-trip")

	// Marshal/unmarshal SignerState, then sign.
	restored := make(map[int]*KeyShare)
	for id, ks := range keyShares {
		ss := NewSignerState(ks)
		data, err := MarshalSignerState(ss)
		require.NoError(t, err)
		got, err := UnmarshalSignerState(data)
		require.NoError(t, err)
		restored[id] = got.KeyShare
	}

	sig := fullSign(t, restored, []int{1, 2, 3}, msg)
	assert.True(t, Verify(restored[1].PublicKey, msg, sig))
}
