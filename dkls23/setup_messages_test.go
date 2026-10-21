package dkls23

import (
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFZeroCommitMsgRoundTrip(t *testing.T) {
	var m FZeroCommitMsg
	rand.Read(m.Commitment[:])
	got := roundTrip(t, "FZeroCommitMsg", &m)
	require.Equal(t, m.Commitment, got.Commitment)
}

func TestFZeroRevealMsgRoundTrip(t *testing.T) {
	var m FZeroRevealMsg
	rand.Read(m.Seed[:])
	rand.Read(m.Salt[:])
	got := roundTrip(t, "FZeroRevealMsg", &m)
	require.Equal(t, m.Seed, got.Seed)
	require.Equal(t, m.Salt, got.Salt)
}

// jsonKeys returns the top-level object keys of v's JSON encoding.
func jsonKeys(t *testing.T, v any) map[string]json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(b, &raw))
	return raw
}

func TestBaseOTReceiverMsgRoundTrip(t *testing.T) {
	t.Parallel()
	state, m, err := BaseOTReceiverRound1(randomBools(t, LambdaC))
	require.NoError(t, err)
	defer state.Zero()

	got := roundTrip(t, "BaseOTReceiverMsg", m)
	require.Len(t, got.R0, LambdaC)
	require.Len(t, got.R1, LambdaC)
	require.Equal(t, m.R0, got.R0)
	require.Equal(t, m.R1, got.R1)

	// Pin the wire format: exactly the keys "r0" and "r1".
	keys := jsonKeys(t, m)
	require.Len(t, keys, 2)
	require.Contains(t, keys, "r0")
	require.Contains(t, keys, "r1")
}

func TestBaseOTSenderMsgRoundTrip(t *testing.T) {
	t.Parallel()
	sigma := randomBools(t, LambdaC)
	state, m, err := BaseOTReceiverRound1(sigma)
	require.NoError(t, err)
	seeds0, seeds1, reply, err := BaseOTSenderRound2(m)
	require.NoError(t, err)

	got := roundTrip(t, "BaseOTSenderMsg", reply)
	require.Len(t, got.M0, LambdaC)
	require.Len(t, got.M1, LambdaC)
	require.Equal(t, reply.M0, got.M0)
	require.Equal(t, reply.M1, got.M1)

	// Pin the wire format: exactly the keys "m0" and "m1".
	keys := jsonKeys(t, reply)
	require.Len(t, keys, 2)
	require.Contains(t, keys, "m0")
	require.Contains(t, keys, "m1")

	// The decoded reply must still finalize to the sender's seeds.
	seeds, err := BaseOTReceiverFinalize(state, got)
	require.NoError(t, err)
	for k := 0; k < LambdaC; k++ {
		if sigma[k] {
			require.Equal(t, seeds1[k], seeds[k], "k=%d", k)
		} else {
			require.Equal(t, seeds0[k], seeds[k], "k=%d", k)
		}
	}
}
