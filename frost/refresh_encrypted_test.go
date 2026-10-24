package frost

import (
	"encoding/json"
	"github.com/chrisalmeida/go-mpc/envelope"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestEncryptedRefreshRejectsForeignAndMalformedCheckpoints(t *testing.T) {
	t.Parallel()
	states := makeSignerStates(fullSetup(t))
	signer, other := states[1], states[2]
	enc := newColdEncryptor(t)
	_, coeffs, seed, err := RefreshRound1(signer)
	require.NoError(t, err)
	state := &RefreshState{Coefficients: coeffs, Seed: seed}
	for _, round := range []int{1, 2} {
		state.Round = round
		blob, err := MarshalRefreshEncrypted(signer, "refresh", state, enc)
		require.NoError(t, err)
		restored, err := UnmarshalRefreshEncrypted(signer, "refresh", round, blob, enc)
		require.NoError(t, err)
		require.Equal(t, state.Seed, restored.Seed)
		require.Equal(t, round, restored.Round)
		_, err = UnmarshalRefreshEncrypted(signer, "other", round, blob, enc)
		require.Error(t, err)
		_, err = UnmarshalRefreshEncrypted(signer, "refresh", 3-round, blob, enc)
		require.Error(t, err)
		_, err = UnmarshalRefreshEncrypted(other, "refresh", round, blob, enc)
		require.Error(t, err)
		context := stateContext(signer.Binding(), refreshKind(round), "refresh", round)
		changed := *state
		changed.Round = 3 - round
		p, err := json.Marshal(&changed)
		require.NoError(t, err)
		forged, err := envelope.Seal(enc, context, p)
		require.NoError(t, err)
		_, err = UnmarshalRefreshEncrypted(signer, "refresh", round, forged, enc)
		require.Error(t, err)
		changed = *state
		changed.Coefficients = changed.Coefficients[:0]
		p, err = json.Marshal(&changed)
		require.NoError(t, err)
		forged, err = envelope.Seal(enc, context, p)
		require.NoError(t, err)
		_, err = UnmarshalRefreshEncrypted(signer, "refresh", round, forged, enc)
		require.Error(t, err)
	}
	_, err = MarshalRefreshEncrypted(nil, "refresh", state, enc)
	require.Error(t, err)
	_, err = MarshalRefreshEncrypted(signer, "refresh", nil, enc)
	require.Error(t, err)
	state.Coefficients = nil
	_, err = MarshalRefreshEncrypted(signer, "refresh", state, enc)
	require.Error(t, err)
	state = refreshFixture()
	state.Round = 0
	_, err = MarshalRefreshEncrypted(signer, "refresh", state, enc)
	require.Error(t, err)
	_, err = UnmarshalRefreshEncrypted(signer, "refresh", 1, []byte("invalid"), enc)
	require.Error(t, err)
}
