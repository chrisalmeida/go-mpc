package frost

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyShareRoundTrip(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	for id, ks := range keyShares {
		got := roundTrip(t, "KeyShare", ks)
		assert.Equal(t, id, got.ID)
		assert.Equal(t, ks.SecretShare, got.SecretShare)
		assert.Equal(t, ks.PublicKey, got.PublicKey)
	}
}

func TestSignerStateRoundTrip(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	ss := NewSignerState(keyShares[1])
	ss.Blacklist[2] = true

	got := roundTrip(t, "SignerState", ss)
	assert.Equal(t, keyShares[1].ID, got.KeyShare.ID)
	assert.True(t, got.Blacklist[2])
}

// TestWireFormatVersion checks that persisted documents carry "version": 1
// and that missing or unknown versions are rejected with a descriptive error.
func TestWireFormatVersion(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	ss := NewSignerState(keyShares[1])

	ksJSON, err := json.Marshal(keyShares[1])
	require.NoError(t, err)
	ssJSON, err := json.Marshal(ss)
	require.NoError(t, err)
	assert.Contains(t, string(ksJSON), `"version":1`)
	assert.Contains(t, string(ssJSON), `"version":1`)
	// SignerState embeds the KeyShare document, which carries its own version.
	assert.Equal(t, 2, strings.Count(string(ssJSON), `"version":1`))

	// Rewrites of the version field and the expected error substring.
	cases := []struct {
		name    string
		rewrite func(s string) string
		want    string
	}{
		{"missing", func(s string) string { return strings.Replace(s, `"version":1,`, ``, 1) }, `missing "version" field (expected 1)`},
		{"unknown 2", func(s string) string { return strings.Replace(s, `"version":1,`, `"version":2,`, 1) }, "unsupported wire format version 2"},
		{"unknown 0", func(s string) string { return strings.Replace(s, `"version":1,`, `"version":0,`, 1) }, "unsupported wire format version 0"},
	}
	for _, tc := range cases {
		t.Run("KeyShare/"+tc.name, func(t *testing.T) {
			doc := tc.rewrite(string(ksJSON))
			require.NotEqual(t, string(ksJSON), doc)
			var ks KeyShare
			err := json.Unmarshal([]byte(doc), &ks)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "key share")
			assert.Contains(t, err.Error(), tc.want)
			_, err = UnmarshalKeyShare([]byte(doc))
			assert.ErrorContains(t, err, tc.want)
		})
		t.Run("SignerState/"+tc.name, func(t *testing.T) {
			// The outer document's version comes first in the encoding.
			doc := tc.rewrite(string(ssJSON))
			require.NotEqual(t, string(ssJSON), doc)
			var got SignerState
			err := json.Unmarshal([]byte(doc), &got)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "signer state")
			assert.Contains(t, err.Error(), tc.want)
			_, err = UnmarshalSignerState([]byte(doc))
			assert.ErrorContains(t, err, tc.want)
		})
	}

	// A bad version on the embedded key share is also rejected.
	inner := strings.Replace(string(ssJSON), `"key_share":{"version":1,`, `"key_share":{"version":7,`, 1)
	require.NotEqual(t, string(ssJSON), inner)
	_, err = UnmarshalSignerState([]byte(inner))
	assert.ErrorContains(t, err, "key share: unsupported wire format version 7")
}

func TestDKGRound1OutputRoundTrip(t *testing.T) {
	t.Parallel()
	cfg := DKGPartyConfig{MyID: 1, AllIDs: []int{1, 2, 3}, Threshold: 3, Context: dkgTestContext}
	out, _, err := DKGRound1(cfg)
	require.NoError(t, err)
	got := roundTrip(t, "DKGRound1Output", out)
	assert.Equal(t, out.ProofR, got.ProofR)
	assert.Equal(t, out.ProofMu, got.ProofMu)
	assert.Equal(t, out.FeldmanCommitments, got.FeldmanCommitments)
	assert.NoError(t, dkgVerifyKnowledge(1, dkgTestContext, got))

	b, err := json.Marshal(out)
	require.NoError(t, err)
	assert.Contains(t, string(b), `"proof_r":"`)
	assert.Contains(t, string(b), `"proof_mu":"`)
}

func TestDKGRound2OutputRoundTrip(t *testing.T) {
	t.Parallel()
	s := runDKGRound1(t, []int{1, 2, 3}, 3)
	out, err := DKGRound2(s.configs[1], s.coeffs[1], s.r1)
	require.NoError(t, err)
	roundTrip(t, "DKGRound2Output", out)
}

func TestRefreshOutputsRoundTrip(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	signer := NewSignerState(keyShares[1])

	r1, coeffs, seed, err := RefreshRound1(signer)
	require.NoError(t, err)
	gotR1 := roundTrip(t, "RefreshRound1Output", r1)
	assert.Equal(t, r1.FeldmanCommitments, gotR1.FeldmanCommitments)
	assert.Equal(t, r1.PairwiseCommitments, gotR1.PairwiseCommitments)
	assert.Equal(t, r1.PairwiseSalts, gotR1.PairwiseSalts)
	assert.Equal(t, r1.SeedCommitment, gotR1.SeedCommitment)
	assert.Equal(t, r1.SeedSalt, gotR1.SeedSalt)

	r2, err := RefreshRound2(signer, coeffs, seed)
	require.NoError(t, err)
	gotR2 := roundTrip(t, "RefreshRound2Output", r2)
	assert.Equal(t, r2.SecretShares, gotR2.SecretShares)
	assert.Equal(t, seed, gotR2.Seed)
}

func TestNonceCommitmentRoundTrip(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	signer := NewSignerState(keyShares[1])
	_, comm, err := SignRound1(signer, []int{1, 2, 3})
	require.NoError(t, err)
	roundTrip(t, "NonceCommitment", comm)
}

func TestSignatureShareRoundTrip(t *testing.T) {
	t.Parallel()
	ss := &SignatureShare{SignerID: 1, Zi: make([]byte, 32)}
	roundTrip(t, "SignatureShare", ss)
}

func TestSignatureRoundTrip(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	sig := fullSign(t, keyShares, []int{1, 2, 3}, []byte("encoding test"))
	roundTrip(t, "Signature", sig)
}
