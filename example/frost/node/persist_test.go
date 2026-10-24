package node

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"

	"github.com/chrisalmeida/go-mpc/frost"
	"github.com/stretchr/testify/require"
	"go-mpc-example/shared"
)

func TestSignerSnapshotRetainsRefreshedEpochAndBlacklist(t *testing.T) {
	t.Parallel()
	ids := []int{1, 2, 3}
	nodes := make([]*Node, len(ids))
	dkgContext := []byte("signer snapshot test " + SessionID())
	r1 := make(map[int]*frost.DKGRound1Output)
	r2 := make(map[int]*frost.DKGRound2Output)
	for i, id := range ids {
		nodes[i] = New(id, ids, 2, dkgContext)
		out, err := nodes[i].DKGRound1()
		require.NoError(t, err)
		r1[id] = out
	}
	for _, n := range nodes {
		out, err := n.DKGRound2(r1)
		require.NoError(t, err)
		r2[n.ID] = out
	}
	for _, n := range nodes {
		require.NoError(t, n.DKGFinalize(r1, r2))
	}
	refresh1 := make(map[int]*frost.RefreshRound1Output)
	refresh2 := make(map[int]*frost.RefreshRound2Output)
	for _, n := range nodes {
		out, err := n.RefreshRound1()
		require.NoError(t, err)
		refresh1[n.ID] = out
	}
	for _, n := range nodes {
		out, err := n.RefreshRound2()
		require.NoError(t, err)
		refresh2[n.ID] = out
	}
	for _, n := range nodes {
		require.NoError(t, n.RefreshFinalize(refresh1, refresh2))
	}
	nodes[0].State.Blacklist[3] = true
	enc := &shared.AESEncryptor{}
	_, err := rand.Read(enc.Key[:])
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "signer.enc")
	require.NoError(t, nodes[0].SaveSignerState(path, enc))
	restored := &Node{}
	expected := nodes[0].State.Binding()
	require.NoError(t, restored.LoadSignerState(path, enc, expected))
	require.Equal(t, 1, restored.Epoch())
	require.True(t, restored.State.Blacklist[3])

	// Rejected binding must not replace the already loaded signer.
	before, err := frost.MarshalSignerState(restored.State)
	require.NoError(t, err)
	wrong := expected
	wrong.Epoch = 0
	require.Error(t, restored.LoadSignerState(path, enc, wrong))
	after, err := frost.MarshalSignerState(restored.State)
	require.NoError(t, err)
	require.Equal(t, before, after)
	_, _, err = restored.SignRound1([]int{1, 3})
	var blacklisted *frost.BlacklistedPartyError
	require.ErrorAs(t, err, &blacklisted)
	require.Equal(t, []int{3}, blacklisted.PartyIDs)

	// The retained refreshed share still signs with an allowed peer.
	message := []byte("restored signer after refresh")
	signers := []int{1, 2}
	states := make(map[int]*frost.Round1State)
	commitments := make(map[int]*frost.NonceCommitment)
	for _, n := range []*Node{restored, nodes[1]} {
		state, commitment, err := n.SignRound1(signers)
		require.NoError(t, err)
		states[n.ID], commitments[n.ID] = state, commitment
	}
	shares := make(map[int]*frost.SignatureShare)
	verification := make(map[int][]byte)
	for _, n := range []*Node{restored, nodes[1]} {
		share, err := n.SignRound2(states[n.ID], &frost.Round2Input{Message: message, AllCommitments: commitments})
		require.NoError(t, err)
		shares[n.ID] = share
		verification[n.ID] = n.KeyShare().VerificationShare
	}
	sig, err := frost.Aggregate(commitments, shares, message, restored.PublicKey(), verification, signers)
	require.NoError(t, err)
	require.True(t, ed25519.Verify(restored.PublicKey(), message, sig.Bytes()))
}
