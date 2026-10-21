package dkls23

import (
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// runRefresh executes a single online refresh round for all parties in setups.
// Returns error from any party, naming the bad sender.
func runRefresh(t *testing.T, setups map[int]*SignerSetup) {
	t.Helper()
	allIDs := setups[firstID(setups)].AllIDs

	// Round 1.
	allR1 := make(map[int]*RefreshRound1Output)
	allCoeffs := make(map[int][]btcec.ModNScalar)
	allSeeds := make(map[int][16]byte)
	for _, id := range allIDs {
		r1, coeffs, seed, err := RefreshRound1(setups[id])
		require.NoError(t, err, "RefreshRound1 party %d", id)
		allR1[id] = r1
		allCoeffs[id] = coeffs
		allSeeds[id] = seed
	}

	// Round 2.
	allR2 := make(map[int]*RefreshRound2Output)
	for _, id := range allIDs {
		r2, err := RefreshRound2(setups[id], allCoeffs[id], allSeeds[id])
		require.NoError(t, err, "RefreshRound2 party %d", id)
		allR2[id] = r2
	}

	// Finalize.
	for _, id := range allIDs {
		err := RefreshFinalize(setups[id], allCoeffs[id], allSeeds[id], allR1, allR2)
		require.NoError(t, err, "RefreshFinalize party %d", id)
	}
}

// firstID returns any key from the map (used when we just need any party).
func firstID(m map[int]*SignerSetup) int {
	for k := range m {
		return k
	}
	return 0
}

// shamirReconstructZq reconstructs a secret at x=0 from t Shamir shares
// given as (x_i, y_i) pairs, using Lagrange interpolation over Zq.
// The shares are ModNScalar values; we convert to big.Int for arithmetic.
func shamirReconstructZq(shares map[int]btcec.ModNScalar) *big.Int {
	q := curveOrder
	secret := new(big.Int)
	ids := make([]int, 0, len(shares))
	for id := range shares {
		ids = append(ids, id)
	}
	for _, xi := range ids {
		num := big.NewInt(1)
		den := big.NewInt(1)
		for _, xj := range ids {
			if xj == xi {
				continue
			}
			num.Mul(num, big.NewInt(int64(-xj)))
			den.Mul(den, big.NewInt(int64(xi-xj)))
		}
		num.Mod(num, q)
		if num.Sign() < 0 {
			num.Add(num, q)
		}
		den.Mod(den, q)
		if den.Sign() < 0 {
			den.Add(den, q)
		}
		lc := new(big.Int).Mul(num, new(big.Int).ModInverse(den, q))
		lc.Mod(lc, q)

		sh := shares[xi]
		shBytes := sh.Bytes()
		shBig := new(big.Int).SetBytes(shBytes[:])

		contrib := new(big.Int).Mul(lc, shBig)
		contrib.Mod(contrib, q)
		secret.Add(secret, contrib)
	}
	secret.Mod(secret, q)
	return secret
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestRefreshPreservesPublicKey verifies that after a full refresh cycle the
// stored public key is unchanged.
func TestRefreshPreservesPublicKey(t *testing.T) {
	t.Parallel()
	allIDs := []int{1, 2, 3}
	setups := fullSetup(t)
	pubKeyBefore := setups[1].PubKey

	runRefresh(t, setups)

	for _, id := range allIDs {
		require.Equal(t, pubKeyBefore, setups[id].PubKey,
			"party %d: public key must be unchanged after refresh", id)
	}
}

// TestRefreshSharesChangedButSameSecret verifies that the Shamir shares
// actually change after refresh, while their Lagrange reconstruction still
// yields the same secret (same public key).
func TestRefreshSharesChangedButSameSecret(t *testing.T) {
	t.Parallel()
	allIDs := []int{1, 2, 3}
	setups := fullSetup(t)

	sharesBefore := make(map[int]btcec.ModNScalar)
	for _, id := range allIDs {
		sharesBefore[id] = setups[id].Share
	}
	pubKeyBefore := setups[1].PubKey

	runRefresh(t, setups)

	sharesAfter := make(map[int]btcec.ModNScalar)
	for _, id := range allIDs {
		sharesAfter[id] = setups[id].Share
	}

	// Shares must have changed (with overwhelming probability).
	changed := false
	for _, id := range allIDs {
		before := sharesBefore[id]
		after := sharesAfter[id]
		if !before.Equals(&after) {
			changed = true
			break
		}
	}
	require.True(t, changed, "at least one share must change after refresh")

	// New shares must still reconstruct the correct public key via G-multiplication.
	// Verify by running a signing session: if shares are consistent with pk, signing works.
	message := []byte("post-refresh signing test")
	r, s := runSigning(t, setups, allIDs, message)
	verifyECDSA(t, pubKeyBefore, message, r, s)
}

// TestRefreshSignAfterRefresh runs a full DKG + pairwise setup + sign,
// then refreshes and signs again with the same public key.
func TestRefreshSignAfterRefresh(t *testing.T) {
	t.Parallel()
	allIDs := []int{1, 2, 3}
	setups := fullSetup(t)
	pubKey := setups[1].PubKey

	// Sign before refresh.
	msg1 := []byte("before refresh")
	r1, s1 := runSigning(t, setups, allIDs, msg1)
	verifyECDSA(t, pubKey, msg1, r1, s1)
	t.Logf("pre-refresh signature verified: r=%x s=%x", r1[:4], s1[:4])

	// Refresh.
	runRefresh(t, setups)

	// Sign after refresh.
	msg2 := []byte("after refresh")
	r2, s2 := runSigning(t, setups, allIDs, msg2)
	verifyECDSA(t, pubKey, msg2, r2, s2)
	t.Logf("post-refresh signature verified: r=%x s=%x", r2[:4], s2[:4])
}

// TestRefreshMultipleEpochs performs two sequential refreshes and confirms
// signing still works and epochs increment correctly.
func TestRefreshMultipleEpochs(t *testing.T) {
	t.Parallel()
	allIDs := []int{1, 2, 3}
	setups := fullSetup(t)
	pubKey := setups[1].PubKey

	for epoch := 1; epoch <= 3; epoch++ {
		runRefresh(t, setups)

		for _, id := range allIDs {
			require.Equal(t, epoch, setups[id].Epoch,
				"party %d: epoch must be %d after refresh %d", id, epoch, epoch)
		}

		msg := []byte{byte(epoch), 0xde, 0xad, 0xbe, 0xef}
		r, s := runSigning(t, setups, allIDs, msg)
		verifyECDSA(t, pubKey, msg, r, s)
		t.Logf("epoch %d signature verified", epoch)
	}
}

// TestRefreshBadFCom tests that a party tampering with a pairwise share in
// round 2 (FCom decommitment failure) is detected and named.
func TestRefreshBadFCom(t *testing.T) {
	t.Parallel()
	allIDs := []int{1, 2, 3}
	setups := fullSetup(t)

	// Round 1 — honest.
	allR1 := make(map[int]*RefreshRound1Output)
	allCoeffs := make(map[int][]btcec.ModNScalar)
	allSeeds := make(map[int][16]byte)
	for _, id := range allIDs {
		r1, coeffs, seed, err := RefreshRound1(setups[id])
		require.NoError(t, err)
		allR1[id] = r1
		allCoeffs[id] = coeffs
		allSeeds[id] = seed
	}

	// Round 2 — party 2 tampers with the share sent to party 1.
	allR2 := make(map[int]*RefreshRound2Output)
	for _, id := range allIDs {
		r2, err := RefreshRound2(setups[id], allCoeffs[id], allSeeds[id])
		require.NoError(t, err)
		allR2[id] = r2
	}
	// Flip a byte in party 2's share for party 1.
	tampered := make([]byte, 32)
	copy(tampered, allR2[2].SecretShares[1])
	tampered[0] ^= 0xff
	allR2[2].SecretShares[1] = tampered

	// Finalize — party 1 must detect party 2 as a bad sender.
	err := RefreshFinalize(setups[1], allCoeffs[1], allSeeds[1], allR1, allR2)
	require.Error(t, err, "party 1 must detect bad FCom from party 2")
	require.Contains(t, err.Error(), "2", "error must identify party 2 as bad sender")
	t.Logf("party 1 correctly detected bad FCom from party 2: %v", err)
}

// TestRefreshBadSeedCommitment tests that a party revealing a different seed
// in round 2 than what was committed in round 1 is detected.
func TestRefreshBadSeedCommitment(t *testing.T) {
	t.Parallel()
	allIDs := []int{1, 2, 3}
	setups := fullSetup(t)

	allR1 := make(map[int]*RefreshRound1Output)
	allCoeffs := make(map[int][]btcec.ModNScalar)
	allSeeds := make(map[int][16]byte)
	for _, id := range allIDs {
		r1, coeffs, seed, err := RefreshRound1(setups[id])
		require.NoError(t, err)
		allR1[id] = r1
		allCoeffs[id] = coeffs
		allSeeds[id] = seed
	}

	allR2 := make(map[int]*RefreshRound2Output)
	for _, id := range allIDs {
		r2, err := RefreshRound2(setups[id], allCoeffs[id], allSeeds[id])
		require.NoError(t, err)
		allR2[id] = r2
	}
	// Party 3 reveals a different seed than committed.
	allR2[3].Seed[0] ^= 0xff

	// Any party receiving party 3's seed must detect the mismatch.
	err := RefreshFinalize(setups[1], allCoeffs[1], allSeeds[1], allR1, allR2)
	require.Error(t, err, "party 1 must detect bad seed from party 3")
	require.Contains(t, err.Error(), "3", "error must identify party 3 as bad sender")
	t.Logf("party 1 correctly detected bad seed commitment from party 3: %v", err)
}

// TestRefreshBadFeldman tests that a party broadcasting Feldman commitments
// inconsistent with the shares they decommit is detected.
func TestRefreshBadFeldman(t *testing.T) {
	t.Parallel()
	allIDs := []int{1, 2, 3}
	setups := fullSetup(t)

	allR1 := make(map[int]*RefreshRound1Output)
	allCoeffs := make(map[int][]btcec.ModNScalar)
	allSeeds := make(map[int][16]byte)
	for _, id := range allIDs {
		r1, coeffs, seed, err := RefreshRound1(setups[id])
		require.NoError(t, err)
		allR1[id] = r1
		allCoeffs[id] = coeffs
		allSeeds[id] = seed
	}

	// Party 2 corrupts its Feldman commitments (the committed polynomial no
	// longer matches the shares that will be revealed in round 2).
	allR1[2].FeldmanCommitments[0][1] ^= 0xff

	allR2 := make(map[int]*RefreshRound2Output)
	for _, id := range allIDs {
		r2, err := RefreshRound2(setups[id], allCoeffs[id], allSeeds[id])
		require.NoError(t, err)
		allR2[id] = r2
	}

	// Party 1 and party 3 must detect party 2's bad Feldman.
	for _, id := range []int{1, 3} {
		err := RefreshFinalize(setups[id], allCoeffs[id], allSeeds[id], allR1, allR2)
		require.Error(t, err, "party %d must detect bad Feldman from party 2", id)
		require.Contains(t, err.Error(), "2", "error must identify party 2 as bad sender")
		t.Logf("party %d correctly detected bad Feldman from party 2: %v", id, err)
	}
}

// TestRefreshBaseOTSeedsStayCorrelated checks the KMOS21 OT re-randomization
// directly: after a refresh, for every directed pair i→j Alice's seed[k]
// still equals Bob's seed_{sigma'[k]}[k] under the new choice bits, the
// unchosen seed is different, every seed actually changed, and a fresh
// OT-extension batch over the refreshed seeds still verifies.
func TestRefreshBaseOTSeedsStayCorrelated(t *testing.T) {
	t.Parallel()
	allIDs := []int{1, 2, 3}
	setups := fullSetup(t)

	type pair struct{ alice, bob int }
	before := map[pair][][]byte{}
	for _, i := range allIDs {
		for _, j := range allIDs {
			if i != j {
				before[pair{i, j}] = append([][]byte(nil), setups[i].AliceBaseOT[j].Seeds...)
			}
		}
	}

	runRefresh(t, setups)

	for _, i := range allIDs {
		for _, j := range allIDs {
			if i == j {
				continue
			}
			alice := setups[i].AliceBaseOT[j] // i is Alice for the i→j direction
			bob := setups[j].BobBaseOT[i]     // j is Bob for the i→j direction
			require.Len(t, alice.Seeds, LambdaC)
			require.Len(t, alice.Sigma, LambdaC)
			require.Len(t, bob.Seeds0, LambdaC)
			require.Len(t, bob.Seeds1, LambdaC)
			changed := 0
			for k := 0; k < LambdaC; k++ {
				chosen, other := bob.Seeds0[k], bob.Seeds1[k]
				if alice.Sigma[k] {
					chosen, other = other, chosen
				}
				require.Equal(t, chosen, alice.Seeds[k], "pair %d→%d instance %d: Alice must hold Bob's seed_{sigma'}", i, j, k)
				require.NotEqual(t, other, alice.Seeds[k], "pair %d→%d instance %d: Alice must not hold the other seed", i, j, k)
				if string(before[pair{i, j}][k]) != string(alice.Seeds[k]) {
					changed++
				}
			}
			require.Equal(t, LambdaC, changed, "pair %d→%d: every seed must be re-randomized", i, j)

			_, _, err := runVOLESession(alice, bob, []byte("post-refresh-batch"))
			require.NoError(t, err, "pair %d→%d: OT extension over refreshed seeds", i, j)
		}
	}
}

// TestRefreshSigningWorksAcrossEpochs runs several refresh cycles and signs
// after each one, which exercises the refreshed base-OT seeds, FZero seeds and
// shares together end to end.
func TestRefreshSigningWorksAcrossEpochs(t *testing.T) {
	t.Parallel()
	allIDs := []int{1, 2, 3}
	setups := fullSetup(t)

	pubKey := setups[1].PubKey
	for i := 0; i < 2; i++ {
		runRefresh(t, setups)
		msg := []byte{0xca, 0xfe, byte(i), 0x00}
		r, s := runSigning(t, setups, allIDs, msg)
		verifyECDSA(t, pubKey, msg, r, s)
	}
}

// TestRefreshShamirConsistency reconstructs the secret from all shares before
// and after refresh and checks the public key is reproduced in both cases.
// Uses the fact that sk*G == PubKey as the consistency check (we never
// reconstruct the raw secret scalar in a threshold context).
func TestRefreshShamirConsistency(t *testing.T) {
	t.Parallel()
	allIDs := []int{1, 2, 3}
	setups := fullSetup(t)

	// Collect shares after DKG + pairwise setup (before refresh).
	sharesBefore := make(map[int]btcec.ModNScalar)
	for _, id := range allIDs {
		sharesBefore[id] = setups[id].Share
	}

	runRefresh(t, setups)

	sharesAfter := make(map[int]btcec.ModNScalar)
	for _, id := range allIDs {
		sharesAfter[id] = setups[id].Share
	}

	// Both before and after: sk*G must equal pubKey.
	// Reconstruct sk before from Shamir: apply Lagrange at x=0 over ALL IDs.
	skBefore := shamirReconstructZq(sharesBefore)
	skAfter := shamirReconstructZq(sharesAfter)

	// Verify sk*G == pubKey.
	var skBeforeScalar btcec.ModNScalar
	skBeforeScalar.SetByteSlice(skBefore.Bytes())
	pkBefore, err := scalarMulGCompressed(&skBeforeScalar)
	require.NoError(t, err)

	var skAfterScalar btcec.ModNScalar
	skAfterScalar.SetByteSlice(skAfter.Bytes())
	pkAfter, err := scalarMulGCompressed(&skAfterScalar)
	require.NoError(t, err)

	require.Equal(t, setups[1].PubKey, pkBefore,
		"pre-refresh: Lagrange reconstruction must reproduce public key")
	require.Equal(t, setups[1].PubKey, pkAfter,
		"post-refresh: Lagrange reconstruction must reproduce public key")
	require.Equal(t, pkBefore, pkAfter,
		"public key must be identical before and after refresh")
	t.Logf("Shamir consistency verified: pubKey=%x...", setups[1].PubKey[:4])
}

// TestRefresh2of3 tests that refresh works in a 2-of-3 threshold configuration.
func TestRefresh2of3(t *testing.T) {
	t.Parallel()
	allIDs := []int{1, 2, 3}
	setups := setupSigners(t, allIDs, 2)
	pubKey := setups[1].PubKey

	runRefresh(t, setups)

	signers := []int{1, 2} // only t=2 parties sign
	msg := []byte("2-of-3 post-refresh signing")
	r, s := runSigning(t, setups, signers, msg)
	verifyECDSA(t, pubKey, msg, r, s)
	t.Logf("2-of-3 post-refresh signature verified")
}
