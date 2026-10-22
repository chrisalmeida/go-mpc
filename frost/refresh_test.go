package frost

import (
	"crypto/ed25519"
	"testing"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runRefresh executes a single refresh round for all parties.
func runRefresh(t testing.TB, signers map[int]*SignerState) {
	t.Helper()
	allIDs := signers[firstID(signers)].KeyShare.AllIDs

	// Round 1.
	allR1 := make(map[int]*RefreshRound1Output)
	allCoeffs := make(map[int][]*edwards25519.Scalar)
	allSeeds := make(map[int][16]byte)
	for _, id := range allIDs {
		r1, coeffs, seed, err := RefreshRound1(signers[id])
		require.NoError(t, err, "RefreshRound1 party %d", id)
		allR1[id] = r1
		allCoeffs[id] = coeffs
		allSeeds[id] = seed
	}

	// Round 2.
	allR2 := make(map[int]*RefreshRound2Output)
	for _, id := range allIDs {
		r2, err := RefreshRound2(signers[id], allCoeffs[id], allSeeds[id])
		require.NoError(t, err, "RefreshRound2 party %d", id)
		allR2[id] = r2
	}

	// Finalize.
	for _, id := range allIDs {
		err := RefreshFinalize(signers[id], allCoeffs[id], allSeeds[id], allR1, allR2)
		require.NoError(t, err, "RefreshFinalize party %d", id)
	}
}

func firstID(m map[int]*SignerState) int {
	for k := range m {
		return k
	}
	return 0
}

func makeSignerStates(keyShares map[int]*KeyShare) map[int]*SignerState {
	states := make(map[int]*SignerState, len(keyShares))
	for id, ks := range keyShares {
		states[id] = NewSignerState(ks)
	}
	return states
}

func TestRefreshPreservesPublicKey(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	states := makeSignerStates(keyShares)
	pkBefore := states[1].KeyShare.PublicKey

	runRefresh(t, states)

	for _, id := range []int{1, 2, 3} {
		assert.Equal(t, pkBefore, states[id].KeyShare.PublicKey,
			"party %d: public key must be unchanged after refresh", id)
	}
}

func TestRefreshSharesChangedButSameSecret(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	states := makeSignerStates(keyShares)

	sharesBefore := make(map[int][]byte)
	for _, id := range []int{1, 2, 3} {
		sharesBefore[id] = make([]byte, ScalarLen)
		copy(sharesBefore[id], states[id].KeyShare.SecretShare)
	}

	runRefresh(t, states)

	// At least one share must have changed.
	changed := false
	for _, id := range []int{1, 2, 3} {
		if string(sharesBefore[id]) != string(states[id].KeyShare.SecretShare) {
			changed = true
			break
		}
	}
	require.True(t, changed, "at least one share must change after refresh")

	// New shares must reconstruct the same public key.
	allIDs := []int{1, 2, 3}
	reconstructed := edwards25519.NewScalar()
	for _, id := range allIDs {
		sk, err := edwards25519.NewScalar().SetCanonicalBytes(states[id].KeyShare.SecretShare)
		require.NoError(t, err)
		lc := lagrangeCoeff(id, allIDs)
		term := edwards25519.NewScalar().Multiply(sk, lc)
		reconstructed.Add(reconstructed, term)
	}
	recoveredPK := edwards25519.NewGeneratorPoint().ScalarBaseMult(reconstructed).Bytes()
	assert.Equal(t, states[1].KeyShare.PublicKey, recoveredPK)
}

func TestRefreshSignAfterRefresh(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	states := makeSignerStates(keyShares)
	pk := states[1].KeyShare.PublicKey

	// Sign before refresh.
	msg1 := []byte("before refresh")
	sig1 := fullSignWithStates(t, states, []int{1, 2, 3}, msg1)
	assert.True(t, Verify(pk, msg1, sig1))

	runRefresh(t, states)

	// Sign after refresh.
	msg2 := []byte("after refresh")
	sig2 := fullSignWithStates(t, states, []int{1, 2, 3}, msg2)
	assert.True(t, Verify(pk, msg2, sig2))
	assert.True(t, ed25519.Verify(ed25519.PublicKey(pk), msg2, sig2.Bytes()))
}

func TestRefreshMultipleEpochs(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	states := makeSignerStates(keyShares)
	pk := states[1].KeyShare.PublicKey

	for epoch := 1; epoch <= 3; epoch++ {
		runRefresh(t, states)

		for _, id := range []int{1, 2, 3} {
			assert.Equal(t, epoch, states[id].Epoch,
				"party %d: epoch must be %d", id, epoch)
		}

		msg := []byte{byte(epoch), 0xde, 0xad}
		sig := fullSignWithStates(t, states, []int{1, 2, 3}, msg)
		assert.True(t, Verify(pk, msg, sig))
	}
}

func TestRefreshBadFCom(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	states := makeSignerStates(keyShares)
	allIDs := []int{1, 2, 3}

	allR1 := make(map[int]*RefreshRound1Output)
	allCoeffs := make(map[int][]*edwards25519.Scalar)
	allSeeds := make(map[int][16]byte)
	for _, id := range allIDs {
		r1, coeffs, seed, err := RefreshRound1(states[id])
		require.NoError(t, err)
		allR1[id] = r1
		allCoeffs[id] = coeffs
		allSeeds[id] = seed
	}

	allR2 := make(map[int]*RefreshRound2Output)
	for _, id := range allIDs {
		r2, err := RefreshRound2(states[id], allCoeffs[id], allSeeds[id])
		require.NoError(t, err)
		allR2[id] = r2
	}

	// Party 2 tampers with share sent to party 1.
	tampered := make([]byte, ScalarLen)
	copy(tampered, allR2[2].SecretShares[1])
	tampered[0] ^= 0xff
	allR2[2].SecretShares[1] = tampered

	err := RefreshFinalize(states[1], allCoeffs[1], allSeeds[1], allR1, allR2)
	require.Error(t, err)
	var cheatErr *CheatingPartyError
	require.ErrorAs(t, err, &cheatErr)
	assert.Contains(t, cheatErr.PartyIDs, 2)
}

func TestRefreshBadSeedCommitment(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	states := makeSignerStates(keyShares)
	allIDs := []int{1, 2, 3}

	allR1 := make(map[int]*RefreshRound1Output)
	allCoeffs := make(map[int][]*edwards25519.Scalar)
	allSeeds := make(map[int][16]byte)
	for _, id := range allIDs {
		r1, coeffs, seed, err := RefreshRound1(states[id])
		require.NoError(t, err)
		allR1[id] = r1
		allCoeffs[id] = coeffs
		allSeeds[id] = seed
	}

	allR2 := make(map[int]*RefreshRound2Output)
	for _, id := range allIDs {
		r2, err := RefreshRound2(states[id], allCoeffs[id], allSeeds[id])
		require.NoError(t, err)
		allR2[id] = r2
	}

	// Party 3 reveals a different seed than committed.
	allR2[3].Seed[0] ^= 0xff

	err := RefreshFinalize(states[1], allCoeffs[1], allSeeds[1], allR1, allR2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "3")
}

func TestRefreshBadFeldman(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	states := makeSignerStates(keyShares)
	allIDs := []int{1, 2, 3}

	allR1 := make(map[int]*RefreshRound1Output)
	allCoeffs := make(map[int][]*edwards25519.Scalar)
	allSeeds := make(map[int][16]byte)
	for _, id := range allIDs {
		r1, coeffs, seed, err := RefreshRound1(states[id])
		require.NoError(t, err)
		allR1[id] = r1
		allCoeffs[id] = coeffs
		allSeeds[id] = seed
	}

	// Use a different valid prime-order point so decoding succeeds and only
	// the Feldman equation can detect the mismatch with the revealed shares.
	changed := edwards25519.NewScalar().Add(allCoeffs[2][0], scalarFromUint64(1))
	if changed.Equal(edwards25519.NewScalar()) == 1 {
		changed.Set(scalarFromUint64(1))
	}
	allR1[2].FeldmanCommitments[0] = edwards25519.NewGeneratorPoint().ScalarBaseMult(changed).Bytes()
	_, err := parseFeldmanCommitments(allR1[2].FeldmanCommitments)
	require.NoError(t, err)

	allR2 := make(map[int]*RefreshRound2Output)
	for _, id := range allIDs {
		r2, err := RefreshRound2(states[id], allCoeffs[id], allSeeds[id])
		require.NoError(t, err)
		allR2[id] = r2
	}

	err = RefreshFinalize(states[1], allCoeffs[1], allSeeds[1], allR1, allR2)
	requireCheating(t, err, 2)
}

func TestRefreshVerificationShareUpdated(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	states := makeSignerStates(keyShares)

	runRefresh(t, states)

	// Verification share must match new secret share * B.
	for _, id := range []int{1, 2, 3} {
		sk, err := edwards25519.NewScalar().SetCanonicalBytes(states[id].KeyShare.SecretShare)
		require.NoError(t, err)
		expected := edwards25519.NewGeneratorPoint().ScalarBaseMult(sk).Bytes()
		assert.Equal(t, expected, states[id].KeyShare.VerificationShare,
			"party %d: verification share must match new secret", id)
	}
}

func TestRefresh2of3(t *testing.T) {
	t.Parallel()
	keyShares, err := buildDKG([]int{1, 2, 3}, 2)
	require.NoError(t, err)
	states := makeSignerStates(keyShares)
	pk := states[1].KeyShare.PublicKey

	runRefresh(t, states)

	// Sign with 2-of-3 subset after refresh.
	msg := []byte("2-of-3 post-refresh")
	sig := fullSignWithStates(t, states, []int{1, 3}, msg)
	assert.True(t, Verify(pk, msg, sig))
}

func TestRefreshMissingRound1(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	states := makeSignerStates(keyShares)
	allIDs := []int{1, 2, 3}

	allR1 := make(map[int]*RefreshRound1Output)
	allCoeffs := make(map[int][]*edwards25519.Scalar)
	allSeeds := make(map[int][16]byte)
	for _, id := range allIDs {
		r1, coeffs, seed, err := RefreshRound1(states[id])
		require.NoError(t, err)
		allR1[id] = r1
		allCoeffs[id] = coeffs
		allSeeds[id] = seed
	}

	allR2 := make(map[int]*RefreshRound2Output)
	for _, id := range allIDs {
		r2, err := RefreshRound2(states[id], allCoeffs[id], allSeeds[id])
		require.NoError(t, err)
		allR2[id] = r2
	}

	// Remove party 2's round 1 output.
	delete(allR1, 2)

	err := RefreshFinalize(states[1], allCoeffs[1], allSeeds[1], allR1, allR2)
	require.Error(t, err)
	var cheatErr *CheatingPartyError
	require.ErrorAs(t, err, &cheatErr)
	assert.Contains(t, cheatErr.PartyIDs, 2)
}

func TestRefreshWrongCommitmentCount(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	states := makeSignerStates(keyShares)
	allIDs := []int{1, 2, 3}

	allR1 := make(map[int]*RefreshRound1Output)
	allCoeffs := make(map[int][]*edwards25519.Scalar)
	allSeeds := make(map[int][16]byte)
	for _, id := range allIDs {
		r1, coeffs, seed, err := RefreshRound1(states[id])
		require.NoError(t, err)
		allR1[id] = r1
		allCoeffs[id] = coeffs
		allSeeds[id] = seed
	}

	// Party 2 sends wrong number of commitments.
	allR1[2].FeldmanCommitments = append(allR1[2].FeldmanCommitments, allR1[2].FeldmanCommitments[0])

	allR2 := make(map[int]*RefreshRound2Output)
	for _, id := range allIDs {
		r2, err := RefreshRound2(states[id], allCoeffs[id], allSeeds[id])
		require.NoError(t, err)
		allR2[id] = r2
	}

	err := RefreshFinalize(states[1], allCoeffs[1], allSeeds[1], allR1, allR2)
	require.Error(t, err)
	var cheatErr *CheatingPartyError
	require.ErrorAs(t, err, &cheatErr)
	assert.Contains(t, cheatErr.PartyIDs, 2)
}

func TestRefreshBlacklistedParty(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	states := makeSignerStates(keyShares)
	states[1].Blacklist[2] = true

	_, _, _, err := RefreshRound1(states[1])
	require.Error(t, err)
	var blErr *BlacklistedPartyError
	assert.ErrorAs(t, err, &blErr)
}

// fullSignWithStates runs a signing session using SignerStates directly.
func fullSignWithStates(t testing.TB, states map[int]*SignerState, signers []int, msg []byte) *Signature {
	t.Helper()

	r1States := make(map[int]*Round1State)
	allComm := make(map[int]*NonceCommitment)
	for _, id := range signers {
		st, comm, err := SignRound1(states[id], signers)
		require.NoError(t, err)
		r1States[id] = st
		allComm[id] = comm
	}

	allShares := make(map[int]*SignatureShare)
	input := &Round2Input{Message: msg, AllCommitments: allComm}
	for _, id := range signers {
		share, err := SignRound2(states[id], r1States[id], input)
		require.NoError(t, err)
		allShares[id] = share
	}

	verShares := make(map[int][]byte)
	for _, id := range signers {
		verShares[id] = states[id].KeyShare.VerificationShare
	}

	sig, err := Aggregate(allComm, allShares, msg, states[signers[0]].KeyShare.PublicKey, verShares, signers)
	require.NoError(t, err)
	return sig
}
