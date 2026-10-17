package dkls23

import (
	"errors"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

// runDKGRounds runs DKG rounds 1 and 2 for all parties and returns the
// messages and private states, without finalizing.
func runDKGRounds(t *testing.T, allIDs []int, threshold int) (allRound1 map[int]*DKGRound1Output, allRound2 map[int]*DKGRound2Output, allPriv map[int]*DKGPrivateState) {
	t.Helper()
	allRound1 = make(map[int]*DKGRound1Output)
	allRound2 = make(map[int]*DKGRound2Output)
	allPriv = make(map[int]*DKGPrivateState)

	// Round 1: commitments only.
	for _, id := range allIDs {
		cfg := DKGPartyConfig{MyID: id, AllIDs: allIDs, Threshold: threshold}
		r1, priv, err := DKGRound1(cfg)
		require.NoError(t, err)
		allRound1[id] = r1
		allPriv[id] = priv
	}

	// Round 2: decommitments, after all commitments are known.
	for _, id := range allIDs {
		cfg := DKGPartyConfig{MyID: id, AllIDs: allIDs, Threshold: threshold}
		peers := map[int]*DKGRound1Output{}
		for _, j := range allIDs {
			if j != id {
				peers[j] = allRound1[j]
			}
		}
		r2, err := DKGRound2(cfg, allPriv[id], peers)
		require.NoError(t, err)
		allRound2[id] = r2
	}
	return
}

// runDKG runs a complete DKG for the given party IDs and threshold.
func runDKG(t *testing.T, allIDs []int, threshold int) (shares map[int]btcec.ModNScalar, pubKey []byte, allRound1 map[int]*DKGRound1Output, allRound2 map[int]*DKGRound2Output, allPriv map[int]*DKGPrivateState) {
	t.Helper()
	allRound1, allRound2, allPriv = runDKGRounds(t, allIDs, threshold)

	shares = make(map[int]btcec.ModNScalar)
	var pk []byte
	for _, id := range allIDs {
		cfg := DKGPartyConfig{MyID: id, AllIDs: allIDs, Threshold: threshold}
		share, pubkey, err := DKGFinalize(cfg, allPriv[id], allRound1, allRound2)
		require.NoError(t, err)
		shares[id] = share
		if pk == nil {
			pk = pubkey
		} else {
			require.Equal(t, pk, pubkey, "all parties must agree on public key")
		}
	}
	pubKey = pk
	return
}

func TestDKG3of3(t *testing.T) {
	allIDs := []int{1, 2, 3}
	shares, pubKey, _, _, _ := runDKG(t, allIDs, 3)
	require.NotNil(t, pubKey)
	require.Len(t, shares, 3)
}

func TestDKG2of3(t *testing.T) {
	allIDs := []int{1, 2, 3}
	shares, pubKey, _, _, _ := runDKG(t, allIDs, 2)
	require.NotNil(t, pubKey)
	require.Len(t, shares, 3)
}

// TestDKGRound1RevealsNothing checks that the round 1 broadcast contains only
// FCom commitments (paper Protocol 7.1 step 2): the Feldman points are not
// released until round 2.
func TestDKGRound1RevealsNothing(t *testing.T) {
	cfg := DKGPartyConfig{MyID: 1, AllIDs: []int{1, 2, 3}, Threshold: 2}
	r1, priv, err := DKGRound1(cfg)
	require.NoError(t, err)
	require.Len(t, priv.FeldmanCommitments, 2)
	require.Len(t, priv.Coeffs, 2)
	require.Len(t, r1.PairwiseCommitments, 2)
	require.NotEqual(t, [32]byte{}, r1.FeldmanCommitment)
	// The commitment opens to exactly the private Feldman vector.
	require.NoError(t, Open(concatFeldman(priv.FeldmanCommitments), r1.FeldmanCommitment, priv.FeldmanSalt))
}

func TestDKGSharesAreShamir(t *testing.T) {
	// Verify that the shares are valid Shamir shares by checking that Lagrange interpolation
	// of all t shares reconstructs the master public key:
	//   sum_i lagrange(i, allIDs) * share_i * G == pk
	allIDs := []int{1, 2, 3}
	shares, pubKey, _, _, _ := runDKG(t, allIDs, 3)

	q := curveOrder

	reconstructed := new(big.Int)
	for _, id := range allIDs {
		lc := lagrangeCoeff(id, allIDs)
		lcBytes := lc.Bytes()
		lcBig := new(big.Int).SetBytes(lcBytes[:])

		sh := shares[id]
		shareBytes := sh.Bytes()
		shareBig := new(big.Int).SetBytes(shareBytes[:])

		term := new(big.Int).Mul(lcBig, shareBig)
		reconstructed.Add(reconstructed, term)
	}
	reconstructed.Mod(reconstructed, q)

	var reconstructedScalar btcec.ModNScalar
	reconstructedScalar.SetByteSlice(reconstructed.Bytes())
	var lhs btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(&reconstructedScalar, &lhs)
	lhs.ToAffine()

	pkPoint, err := compressedToPoint(pubKey)
	require.NoError(t, err)
	pkPoint.ToAffine()

	require.True(t, lhs.X.Equals(&pkPoint.X) && lhs.Y.Equals(&pkPoint.Y),
		"Lagrange interpolation of shares must equal the master public key")
}

// TestDKGFeldmanDecommitMismatch: a party reveals Feldman commitments that do
// not match what it committed to in round 1.
func TestDKGFeldmanDecommitMismatch(t *testing.T) {
	allIDs := []int{1, 2, 3}
	allRound1, allRound2, allPriv := runDKGRounds(t, allIDs, 2)

	allRound2[2].FeldmanCommitments[0][1] ^= 0xff

	cfg := DKGPartyConfig{MyID: 1, AllIDs: allIDs, Threshold: 2}
	_, _, err := DKGFinalize(cfg, allPriv[1], allRound1, allRound2)
	require.Error(t, err)
	var cheat *CheatingPartyError
	require.True(t, errors.As(err, &cheat))
	require.Equal(t, []int{2}, cheat.PartyIDs)
}

// TestDKGBadFeldmanCommitment: a party changes its polynomial after seeing the
// others' commitments (rushing adversary). Its round 1 commitment no longer
// opens to the revealed Feldman points.
func TestDKGBadFeldmanCommitment(t *testing.T) {
	allIDs := []int{1, 2, 3}
	allRound1, allRound2, allPriv := runDKGRounds(t, allIDs, 2)

	// Party 2 swaps in a fresh polynomial for round 2 but cannot change the
	// round 1 commitment the others already hold.
	cfg2 := DKGPartyConfig{MyID: 2, AllIDs: allIDs, Threshold: 2}
	_, priv2New, err := DKGRound1(cfg2)
	require.NoError(t, err)
	peers := map[int]*DKGRound1Output{1: allRound1[1], 3: allRound1[3]}
	r2New, err := DKGRound2(cfg2, priv2New, peers)
	require.NoError(t, err)
	allRound2[2] = r2New

	cfg := DKGPartyConfig{MyID: 1, AllIDs: allIDs, Threshold: 2}
	_, _, err = DKGFinalize(cfg, allPriv[1], allRound1, allRound2)
	require.Error(t, err, "must detect party 2 changing its committed polynomial")
	var cheat *CheatingPartyError
	require.True(t, errors.As(err, &cheat))
	require.Equal(t, []int{2}, cheat.PartyIDs)
}

// TestDKGWrongCommitmentCount: a party commits to a polynomial of the wrong
// degree. Even with consistent commitments it must be rejected.
func TestDKGWrongCommitmentCount(t *testing.T) {
	allIDs := []int{1, 2, 3}
	allRound1, allRound2, allPriv := runDKGRounds(t, allIDs, 2)

	// Party 2 regenerates with threshold 3 (degree-2 polynomial) and commits consistently.
	cfg2 := DKGPartyConfig{MyID: 2, AllIDs: allIDs, Threshold: 3}
	r1New, privNew, err := DKGRound1(cfg2)
	require.NoError(t, err)
	peers := map[int]*DKGRound1Output{1: allRound1[1], 3: allRound1[3]}
	r2New, err := DKGRound2(cfg2, privNew, peers)
	require.NoError(t, err)
	allRound1[2] = r1New
	allRound2[2] = r2New

	cfg := DKGPartyConfig{MyID: 1, AllIDs: allIDs, Threshold: 2}
	_, _, err = DKGFinalize(cfg, allPriv[1], allRound1, allRound2)
	require.Error(t, err, "must reject wrong Feldman commitment count")
	var cheat *CheatingPartyError
	require.True(t, errors.As(err, &cheat))
	require.Equal(t, []int{2}, cheat.PartyIDs)
}

func TestDKGBadShare(t *testing.T) {
	allIDs := []int{1, 2, 3}
	allRound1, allRound2, allPriv := runDKGRounds(t, allIDs, 2)

	// Party 2 sends a bad share to party 1 (wrong value but re-committed).
	badShare := make([]byte, 32)
	badShare[31] = 0x42
	allRound2[2].SecretShares[1] = badShare

	com, salt, err := Commit(badShare)
	require.NoError(t, err)
	allRound1[2].PairwiseCommitments[1] = com
	allRound2[2].PairwiseSalts[1] = salt

	// Party 1 finalizes — Feldman check must fail.
	cfg := DKGPartyConfig{MyID: 1, AllIDs: allIDs, Threshold: 2}
	_, _, err = DKGFinalize(cfg, allPriv[1], allRound1, allRound2)
	require.Error(t, err, "must detect bad share from party 2")
}

func TestDKGShareDecommitMismatch(t *testing.T) {
	allIDs := []int{1, 2, 3}
	allRound1, allRound2, allPriv := runDKGRounds(t, allIDs, 2)

	tampered := make([]byte, 32)
	copy(tampered, allRound2[2].SecretShares[1])
	tampered[0] ^= 0x01
	allRound2[2].SecretShares[1] = tampered

	cfg := DKGPartyConfig{MyID: 1, AllIDs: allIDs, Threshold: 2}
	_, _, err := DKGFinalize(cfg, allPriv[1], allRound1, allRound2)
	require.Error(t, err, "must detect share not matching its commitment")
}

func TestDKGMissingMessages(t *testing.T) {
	allIDs := []int{1, 2, 3}
	allRound1, allRound2, allPriv := runDKGRounds(t, allIDs, 2)

	delete(allRound2, 3)
	cfg := DKGPartyConfig{MyID: 1, AllIDs: allIDs, Threshold: 2}
	_, _, err := DKGFinalize(cfg, allPriv[1], allRound1, allRound2)
	require.Error(t, err)
	var cheat *CheatingPartyError
	require.True(t, errors.As(err, &cheat))
	require.Equal(t, []int{3}, cheat.PartyIDs)

	_, _, err = DKGFinalize(cfg, nil, allRound1, allRound2)
	require.Error(t, err)
}

func TestDKGRound2RequiresAllCommitments(t *testing.T) {
	allIDs := []int{1, 2, 3}
	cfg := DKGPartyConfig{MyID: 1, AllIDs: allIDs, Threshold: 2}
	_, priv, err := DKGRound1(cfg)
	require.NoError(t, err)

	// Round 2 may only be run once notified of all other parties' commitments.
	_, err = DKGRound2(cfg, priv, map[int]*DKGRound1Output{})
	require.Error(t, err)
	var inputErr *InvalidInputError
	require.True(t, errors.As(err, &inputErr))

	_, err = DKGRound2(cfg, nil, map[int]*DKGRound1Output{})
	require.Error(t, err)
}

func TestDKGPrivateStateZero(t *testing.T) {
	cfg := DKGPartyConfig{MyID: 1, AllIDs: []int{1, 2}, Threshold: 2}
	_, priv, err := DKGRound1(cfg)
	require.NoError(t, err)
	priv.Zero()
	for _, c := range priv.Coeffs {
		require.True(t, c.IsZero())
	}
	var nilState *DKGPrivateState
	nilState.Zero() // must not panic
}

func TestDKGRound1InvalidThreshold(t *testing.T) {
	cfg := DKGPartyConfig{MyID: 1, AllIDs: []int{1, 2, 3}, Threshold: 0}
	_, _, err := DKGRound1(cfg)
	require.Error(t, err)
	var inputErr *InvalidInputError
	require.True(t, errors.As(err, &inputErr))

	cfg.Threshold = 4
	_, _, err = DKGRound1(cfg)
	require.Error(t, err)
	require.True(t, errors.As(err, &inputErr))
}

func TestDKGRound1MyIDNotInAllIDs(t *testing.T) {
	cfg := DKGPartyConfig{MyID: 99, AllIDs: []int{1, 2, 3}, Threshold: 2}
	_, _, err := DKGRound1(cfg)
	require.Error(t, err)
	var inputErr *InvalidInputError
	require.True(t, errors.As(err, &inputErr))
	require.Contains(t, inputErr.Detail, "99")
}

func TestDKGRound1DuplicateIDs(t *testing.T) {
	cfg := DKGPartyConfig{MyID: 1, AllIDs: []int{1, 1, 2}, Threshold: 2}
	_, _, err := DKGRound1(cfg)
	require.Error(t, err)
	var inputErr *InvalidInputError
	require.True(t, errors.As(err, &inputErr))
	require.Contains(t, inputErr.Detail, "duplicate")
}

func TestDKGRound1NegativeID(t *testing.T) {
	cfg := DKGPartyConfig{MyID: -1, AllIDs: []int{-1, 1, 2}, Threshold: 2}
	_, _, err := DKGRound1(cfg)
	require.Error(t, err)
	var inputErr *InvalidInputError
	require.True(t, errors.As(err, &inputErr))
	require.Contains(t, inputErr.Detail, "out of range")
}

func TestDKGRound1ZeroID(t *testing.T) {
	cfg := DKGPartyConfig{MyID: 0, AllIDs: []int{0, 1, 2}, Threshold: 2}
	_, _, err := DKGRound1(cfg)
	require.Error(t, err)
	var inputErr *InvalidInputError
	require.True(t, errors.As(err, &inputErr))
	require.Contains(t, inputErr.Detail, "out of range")
}

func TestDKG2of3Sign2of3(t *testing.T) {
	t.Parallel()
	allIDs := []int{1, 2, 3}
	setups := setupSigners(t, allIDs, 2)
	signers := []int{1, 3}
	msg := []byte("2-of-3 threshold signing")
	r, s := runSigning(t, setups, signers, msg)
	verifyECDSA(t, setups[1].PubKey, msg, r, s)
}

func TestDKG2of2(t *testing.T) {
	t.Parallel()
	allIDs := []int{1, 2}
	setups := setupSigners(t, allIDs, 2)
	msg := []byte("2-of-2 minimal threshold")
	r, s := runSigning(t, setups, allIDs, msg)
	verifyECDSA(t, setups[1].PubKey, msg, r, s)
}

func TestValidatePartyIDsEmpty(t *testing.T) {
	err := validatePartyIDs([]int{}, "test")
	require.NoError(t, err)
}

func TestValidatePartyIDsLargeID(t *testing.T) {
	err := validatePartyIDs([]int{1, maxPartyID + 1}, "test")
	require.Error(t, err)
	require.Contains(t, err.Error(), "out of range")
}
