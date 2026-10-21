package dkls23

// Proactive share refresh for DKLS23 (online variant).
//
// Based on KMOS21: "Refresh When You Wake Up: Proactive Threshold Wallets with
// Offline Devices" (Kondi/Magri/Orlandi/Shlomovits, IEEE S&P 2021).
// https://eprint.iacr.org/2019/1328
//
// # Protocol summary (all parties online)
//
// Each party Pi samples a zero-constant degree-(t-1) polynomial:
//
//	f_i(x) = δ_{i,1}·x + δ_{i,2}·x² + … + δ_{i,t-1}·x^{t-1}
//
// so f_i(0) = 0.  Each Pj receives f_i(j) from Pi via FCom (commit-then-reveal)
// and verifies consistency with the Feldman commitments {C_{i,k} = δ_{i,k}·G}.
//
// New Shamir share for Pj:
//
//	share_j' = share_j + Σ_i f_i(j)  mod q
//
// Secret preserved: Lagrange(share', 0) = Lagrange(share, 0) since Σ_i f_i(0) = 0.
//
// Base-OT re-randomization (KMOS21 §4 – OT re-randomization):
// The only persistent OT material is the λc base-OT seed pairs per directed
// pair (DKLS23 §8.2); the OT-extension batches are regenerated per signing
// session and never stored. A public SHAKE-256 stream seeded from a
// collectively committed combined seed drives per-instance bit flips and mask
// XORs that maintain the base-OT correlation invariant:
// Alice's seed[k] = Bob's seed_{sigma[k]}[k].
//
// FZero seed refresh: per-pair seeds re-derived from the combined seed so that
// zero-sharing remains unbiased in future signing sessions.
//
// Impossibility note: for n=3, t=3, t_rho ≥ 2(t-1) = 4 > n, so all three
// parties must be online (proactive security requires full participation).

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"golang.org/x/crypto/sha3"
)

// refreshContribution identifies an applied local contribution using existing
// public values. It is bookkeeping, not a protocol message or hash input.
type refreshContribution struct {
	publicKey string
	partyID   int
	seed      [16]byte
}

// RefreshRound1Output is broadcast by each party Pi in refresh round 1.
// It contains Feldman commitments for a zero-constant polynomial and FCom
// commitments to the pairwise evaluations and a fresh per-party seed.
type RefreshRound1Output struct {
	// FeldmanCommitments are the t-1 compressed EC points C_{i,k} = δ_{i,k}·G
	// for k = 1..t-1.  No k=0 term: the polynomial is zero-constant, so f_i(0)=0.
	FeldmanCommitments [][]byte
	// PairwiseCommitments[j] is FCom(f_i(j)) for peer j.
	PairwiseCommitments map[int][32]byte
	// PairwiseSalts[j] is the FCom salt for the commitment to f_i(j).
	PairwiseSalts map[int][SaltLen]byte
	// SeedCommitment is FCom of this party's 16-byte seed contribution.
	SeedCommitment [32]byte
	// SeedSalt is the FCom salt for the seed commitment.
	SeedSalt [SaltLen]byte
}

// RefreshRound2Output contains the decommitments Pi broadcasts in refresh round 2.
type RefreshRound2Output struct {
	// SecretShares[j] is f_i(j) encoded as 32-byte big-endian for each peer j.
	SecretShares map[int][]byte
	// Seed is the 16-byte seed Pi contributed in round 1.
	Seed [16]byte
}

// RefreshRound1 executes round 1 of the proactive refresh protocol for setup.MyID.
//
// Pi samples a zero-constant polynomial f_i(x) = δ_1·x + … + δ_{t-1}·x^{t-1},
// broadcasts Feldman commitments C_{i,k} = δ_k·G for k = 1..t-1, commits to
// f_i(j) for each peer j via FCom, and commits to a fresh 16-byte seed that will
// be used to re-randomize base-OT and FZero state in RefreshFinalize.
//
// Returns the broadcast output, the polynomial coefficients (kept private until
// RefreshRound2), and the seed (kept private until RefreshRound2).
func RefreshRound1(setup *SignerSetup) (*RefreshRound1Output, []btcec.ModNScalar, [16]byte, error) {
	setup.mu.RLock()
	defer setup.mu.RUnlock()
	t := setup.Threshold

	// Sample t-1 coefficients δ_1, …, δ_{t-1} for the zero-constant polynomial.
	// coeffs[k] = δ_{k+1} (the coefficient of x^{k+1}), so f(x) = Σ coeffs[k]·x^{k+1}.
	coeffs := make([]btcec.ModNScalar, t-1)
	for k := 0; k < t-1; k++ {
		c, err := sampleScalar()
		if err != nil {
			return nil, nil, [16]byte{}, fmt.Errorf("dkls23 RefreshRound1: sample coeff %d: %w", k+1, err)
		}
		coeffs[k] = c
	}

	// Compute Feldman commitments C_{i,k} = δ_k · G for k = 1..t-1.
	feldman := make([][]byte, t-1)
	for k := 0; k < t-1; k++ {
		pt, err := scalarMulGCompressed(&coeffs[k])
		if err != nil {
			return nil, nil, [16]byte{}, fmt.Errorf("dkls23 RefreshRound1: Feldman commitment k=%d: %w", k+1, err)
		}
		feldman[k] = pt
	}

	// Commit to f_i(j) for each peer j via FCom.
	pairwiseComs := make(map[int][32]byte)
	pairwiseSalts := make(map[int][SaltLen]byte)
	for _, j := range setup.AllIDs {
		if j == setup.MyID {
			continue
		}
		share := evalZeroConstPoly(coeffs, uint32(j))
		shareArr := share.Bytes()
		shareBytes := shareArr[:]

		com, salt, err := Commit(shareBytes)
		for i := range shareArr {
			shareArr[i] = 0
		}
		if err != nil {
			return nil, nil, [16]byte{}, fmt.Errorf("dkls23 RefreshRound1: commit share for %d: %w", j, err)
		}
		pairwiseComs[j] = com
		pairwiseSalts[j] = salt
	}

	// Sample a fresh 16-byte seed and commit to it.
	var mySeed [16]byte
	if _, err := rand.Read(mySeed[:]); err != nil {
		return nil, nil, [16]byte{}, fmt.Errorf("dkls23 RefreshRound1: sample seed: %w", err)
	}
	seedCom, seedSalt, err := Commit(mySeed[:])
	if err != nil {
		return nil, nil, [16]byte{}, fmt.Errorf("dkls23 RefreshRound1: commit seed: %w", err)
	}

	out := &RefreshRound1Output{
		FeldmanCommitments:  feldman,
		PairwiseCommitments: pairwiseComs,
		PairwiseSalts:       pairwiseSalts,
		SeedCommitment:      seedCom,
		SeedSalt:            seedSalt,
	}
	return out, coeffs, mySeed, nil
}

// RefreshRound2 decommits pairwise evaluations and reveals the seed.
// coeffs and mySeed must be the values returned by RefreshRound1.
func RefreshRound2(setup *SignerSetup, coeffs []btcec.ModNScalar, mySeed [16]byte) (*RefreshRound2Output, error) {
	setup.mu.RLock()
	defer setup.mu.RUnlock()
	secretShares := make(map[int][]byte)
	for _, j := range setup.AllIDs {
		if j == setup.MyID {
			continue
		}
		share := evalZeroConstPoly(coeffs, uint32(j))
		shareArr := share.Bytes()
		shareBytes := make([]byte, 32)
		copy(shareBytes, shareArr[:])
		for i := range shareArr {
			shareArr[i] = 0
		}
		secretShares[j] = shareBytes
	}
	return &RefreshRound2Output{SecretShares: secretShares, Seed: mySeed}, nil
}

// RefreshFinalize verifies all received round 1/2 messages and, if all checks
// pass, mutates setup in place:
//
//  1. Verifies FCom decommitment of f_j(myID) for each sender j.
//  2. Verifies Feldman consistency: f_j(myID)·G = Σ_{k=1}^{t-1} C_{j,k}·myID^k.
//  3. Verifies seed FCom decommitment.
//  4. Derives combinedSeed = XOR of all n party seeds.
//  5. Updates the Shamir share: share += Σ_j f_j(myID) mod q.
//  6. Re-randomizes all base-OT seeds via OT re-randomization (KMOS21 §4).
//  7. Derives new per-pair FZero seeds from combinedSeed.
//  8. Increments setup.Epoch and clears the record of used session ids (the
//     new seeds re-key everything a session id feeds into).
//
// Returns an error naming all bad senders if any verification fails; setup is
// NOT modified in that case.
// A completed local seed contribution cannot be applied again on this setup.
// This in-memory replay record does not replace durable caller-side routing
// and replay protection after state restoration.
func RefreshFinalize(
	setup *SignerSetup,
	coeffs []btcec.ModNScalar,
	mySeed [16]byte,
	allRound1 map[int]*RefreshRound1Output,
	allRound2 map[int]*RefreshRound2Output,
) error {
	setup.mu.Lock()
	defer setup.mu.Unlock()
	if err := checkBlacklist(setup, setup.AllIDs, "RefreshFinalize"); err != nil {
		return err
	}
	contribution := refreshContribution{publicKey: string(setup.PubKey), partyID: setup.MyID, seed: mySeed}
	if setup.completedRefresh[contribution] {
		return &CorruptStateError{Phase: "RefreshFinalize", Detail: "local refresh contribution already applied"}
	}
	var badSenders []int

	// Validate messages and accumulate share additions from peers.
	// We separate validation from mutation so setup is unchanged on error.
	type peerContrib struct {
		shareVal btcec.ModNScalar
		seed     [16]byte
	}
	peerContribs := make(map[int]peerContrib, len(setup.AllIDs)-1)

	for _, j := range setup.AllIDs {
		if j == setup.MyID {
			continue
		}
		r1j := allRound1[j]
		r2j := allRound2[j]
		if r1j == nil || r2j == nil {
			badSenders = append(badSenders, j)
			continue
		}

		// Step 1: Verify FCom decommitment of f_j(myID).
		shareBytes := r2j.SecretShares[setup.MyID]
		if len(shareBytes) != 32 {
			badSenders = append(badSenders, j)
			continue
		}
		com, ok1 := r1j.PairwiseCommitments[setup.MyID]
		salt, ok2 := r1j.PairwiseSalts[setup.MyID]
		if !ok1 || !ok2 {
			badSenders = append(badSenders, j)
			continue
		}
		if err := Open(shareBytes, com, salt); err != nil {
			badSenders = append(badSenders, j)
			continue
		}

		// Step 2: Feldman verification: f_j(myID)·G = Σ_{k=1}^{t-1} C_{j,k}·myID^k.
		// The committed polynomial must have exactly t-1 non-constant coefficients.
		if len(r1j.FeldmanCommitments) != setup.Threshold-1 {
			badSenders = append(badSenders, j)
			continue
		}
		var shareVal btcec.ModNScalar
		if overflow := shareVal.SetByteSlice(shareBytes); overflow {
			badSenders = append(badSenders, j)
			continue
		}
		if err := refreshFeldmanVerify(&shareVal, setup.MyID, r1j.FeldmanCommitments); err != nil {
			badSenders = append(badSenders, j)
			continue
		}

		// Step 3: Verify seed FCom decommitment.
		if err := Open(r2j.Seed[:], r1j.SeedCommitment, r1j.SeedSalt); err != nil {
			badSenders = append(badSenders, j)
			continue
		}

		peerContribs[j] = peerContrib{shareVal: shareVal, seed: r2j.Seed}
	}

	if len(badSenders) > 0 {
		return &CheatingPartyError{PartyIDs: badSenders, Phase: "RefreshFinalize", Detail: "share, Feldman, or seed verification failed"}
	}

	// Step 4: Derive combinedSeed = XOR of all n party seeds (including mine).
	combinedSeed := mySeed
	for _, j := range setup.AllIDs {
		if j == setup.MyID {
			continue
		}
		pc := peerContribs[j]
		for b := 0; b < 16; b++ {
			combinedSeed[b] ^= pc.seed[b]
		}
	}

	// Step 5: Update Shamir share.
	// new_share = old_share + f_i(myID) + Σ_{j≠i} f_j(myID)  mod q.
	myContrib := evalZeroConstPoly(coeffs, uint32(setup.MyID))
	var shareAdd btcec.ModNScalar
	shareAdd.Set(&myContrib)
	for _, j := range setup.AllIDs {
		if j == setup.MyID {
			continue
		}
		pc := peerContribs[j]
		shareAdd.Add(&pc.shareVal)
	}
	var newShare btcec.ModNScalar
	newShare.Add2(&setup.Share, &shareAdd)

	// Step 6: Re-randomize base-OT seeds into temporary maps.
	// Built separately so setup is untouched if any step fails.
	newAlice := make(map[int]*BaseOTReceiverSeeds, len(setup.AllIDs)-1)
	newBob := make(map[int]*BaseOTSenderSeeds, len(setup.AllIDs)-1)
	for _, j := range setup.AllIDs {
		if j == setup.MyID {
			continue
		}
		a, err := refreshBaseOTReceiver(setup.AliceBaseOT[j], setup.MyID, j, combinedSeed)
		if err != nil {
			return fmt.Errorf("dkls23 RefreshFinalize: refreshBaseOTReceiver(%d→%d): %w", setup.MyID, j, err)
		}
		b, err := refreshBaseOTSender(setup.BobBaseOT[j], j, setup.MyID, combinedSeed)
		if err != nil {
			return fmt.Errorf("dkls23 RefreshFinalize: refreshBaseOTSender(%d→%d): %w", j, setup.MyID, err)
		}
		newAlice[j] = a
		newBob[j] = b
	}

	// Step 7: Derive new FZero seeds from combinedSeed.
	newFZeroSeeds := make(map[int][16]byte, len(setup.AllIDs)-1)
	for _, j := range setup.AllIDs {
		if j == setup.MyID {
			continue
		}
		newFZeroSeeds[j] = deriveFZeroSeed(combinedSeed, setup.MyID, j)
	}

	myContrib.Zero()
	shareAdd.Zero()

	// All mutations succeed atomically from this point.
	setup.Share = newShare
	setup.AliceBaseOT = newAlice
	setup.BobBaseOT = newBob
	setup.FZeroSeeds = newFZeroSeeds
	setup.Epoch++
	// Every quantity derived from a session id (OT-extension PRF rows, OT
	// output seeds, FZero values) is keyed by seeds that were just replaced,
	// so ids used in earlier epochs cannot reproduce anything under the new
	// seeds. Clearing the record bounds its growth to one epoch.
	setup.SessionIDs = make(map[string]int)
	if setup.completedRefresh == nil {
		setup.completedRefresh = make(map[refreshContribution]bool)
	}
	setup.completedRefresh[contribution] = true
	return nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// evalZeroConstPoly evaluates the zero-constant polynomial
//
//	f(x) = coeffs[0]·x + coeffs[1]·x² + … + coeffs[t-2]·x^{t-1}
//
// at x.  The polynomial has no constant term, so f(0) = 0.
// All arithmetic is constant-time via ModNScalar.
func evalZeroConstPoly(coeffs []btcec.ModNScalar, x uint32) btcec.ModNScalar {
	var result, xScalar, xPow btcec.ModNScalar
	xScalar.SetInt(x)
	xPow.Set(&xScalar) // x^1
	for _, c := range coeffs {
		var term btcec.ModNScalar
		term.Mul2(&c, &xPow)
		result.Add(&term)
		xPow.Mul(&xScalar)
	}
	return result
}

// refreshFeldmanVerify checks that share·G = Σ_{k=1}^{t-1} C_{i,k} · x^k
// for a zero-constant polynomial (no constant term commitment).
// nonConstFeldman[k] is the compressed point for the (k+1)-th coefficient.
func refreshFeldmanVerify(share *btcec.ModNScalar, x int, nonConstFeldman [][]byte) error {
	if len(nonConstFeldman) == 0 {
		// t = 1: the zero-constant polynomial is f(x) = 0 for all x.
		if !share.IsZero() {
			return errors.New("dkls23: refresh Feldman failed: nonzero share for zero-degree polynomial")
		}
		return nil
	}

	var xScalar, xPow btcec.ModNScalar
	xScalar.SetInt(uint32(x))
	xPow.Set(&xScalar) // x^1

	// RHS = Σ_{k=1}^{t-1} C_{i,k} · x^k.
	rhs := newCurvePoint()
	for _, commitBytes := range nonConstFeldman {
		Cik, err := compressedToPoint(commitBytes)
		if err != nil {
			return fmt.Errorf("dkls23: parse refresh Feldman commitment: %w", err)
		}
		scaled := scalarMul(&xPow, Cik)
		rhs.Add(scaled)
		xPow.Mul(&xScalar)
	}

	// LHS = share · G.
	lhs := scalarMulG(share)

	// Complete group equality also covers the zero-share / identity case.
	if lhs.Equal(rhs) != 1 {
		return errors.New("dkls23: refresh Feldman verification failed: share inconsistent with commitments")
	}
	return nil
}

// refreshBaseOTSender applies KMOS21 OT re-randomization to Bob's base-OT
// sender seed pairs for the directed pair (aliceID → bobID). For each instance
// k the public stream yields a bit b'_k and masks (r0_k, r1_k); the pair is
// swapped when b'_k = 1 and then masked. Returns a new state; the original is
// not modified.
func refreshBaseOTSender(state *BaseOTSenderSeeds, aliceID, bobID int, combinedSeed [16]byte) (*BaseOTSenderSeeds, error) {
	if state == nil || len(state.Seeds0) != LambdaC || len(state.Seeds1) != LambdaC {
		return nil, errors.New("dkls23 refreshBaseOTSender: base-OT sender seeds must have LambdaC entries")
	}
	xof := newVOLERefreshStream(combinedSeed, aliceID, bobID)

	newSeeds0 := make([][]byte, LambdaC)
	newSeeds1 := make([][]byte, LambdaC)
	var bPrimeBuf [1]byte
	var r0, r1 [32]byte
	for k := 0; k < LambdaC; k++ {
		xof.Read(bPrimeBuf[:])
		bPrime := (bPrimeBuf[0] & 1) == 1
		xof.Read(r0[:])
		xof.Read(r1[:])
		if len(state.Seeds0[k]) != 32 || len(state.Seeds1[k]) != 32 {
			return nil, fmt.Errorf("dkls23 refreshBaseOTSender: seed %d must be 32 bytes", k)
		}

		// b' is public (derived from the committed combined seed), so the swap
		// may branch on it. The seeds themselves are only XORed.
		src0, src1 := state.Seeds0[k], state.Seeds1[k]
		if bPrime {
			src0, src1 = src1, src0
		}
		n0 := make([]byte, 32)
		n1 := make([]byte, 32)
		for b := 0; b < 32; b++ {
			n0[b] = src0[b] ^ r0[b]
			n1[b] = src1[b] ^ r1[b]
		}
		newSeeds0[k] = n0
		newSeeds1[k] = n1
	}
	return &BaseOTSenderSeeds{Seeds0: newSeeds0, Seeds1: newSeeds1}, nil
}

// refreshBaseOTReceiver applies KMOS21 OT re-randomization to Alice's base-OT
// receiver seeds for the directed pair (aliceID → bobID), mirroring
// refreshBaseOTSender: sigma'_k = sigma_k XOR b'_k and the seed is masked with
// r_{sigma'_k}. The mask selection is branchless because sigma is secret.
// Returns a new state; the original is not modified.
func refreshBaseOTReceiver(state *BaseOTReceiverSeeds, aliceID, bobID int, combinedSeed [16]byte) (*BaseOTReceiverSeeds, error) {
	if state == nil || len(state.Seeds) != LambdaC || len(state.Sigma) != LambdaC {
		return nil, errors.New("dkls23 refreshBaseOTReceiver: base-OT receiver seeds must have LambdaC entries")
	}
	xof := newVOLERefreshStream(combinedSeed, aliceID, bobID)

	newSeeds := make([][]byte, LambdaC)
	newSigma := make([]bool, LambdaC)
	var bPrimeBuf [1]byte
	var r0, r1 [32]byte
	for k := 0; k < LambdaC; k++ {
		xof.Read(bPrimeBuf[:])
		bPrime := (bPrimeBuf[0] & 1) == 1
		xof.Read(r0[:])
		xof.Read(r1[:])
		if len(state.Seeds[k]) != 32 {
			return nil, fmt.Errorf("dkls23 refreshBaseOTReceiver: seed %d must be 32 bytes", k)
		}

		newSigma[k] = state.Sigma[k] != bPrime // XOR of booleans

		// Branchless mask selection: start with r0, conditionally overwrite with r1.
		sel := int(condUint32(newSigma[k]))
		mask := r0
		subtle.ConstantTimeCopy(sel, mask[:], r1[:])
		n := make([]byte, 32)
		for b := 0; b < 32; b++ {
			n[b] = state.Seeds[k][b] ^ mask[b]
		}
		newSeeds[k] = n
	}
	return &BaseOTReceiverSeeds{Seeds: newSeeds, Sigma: newSigma}, nil
}

// newVOLERefreshStream returns a SHAKE-256 XOF for re-randomizing the base-OT
// seeds of the directed VOLE pair (aliceID → bobID).
func newVOLERefreshStream(combinedSeed [16]byte, aliceID, bobID int) sha3.ShakeHash {
	xof := sha3.NewShake256()
	xof.Write([]byte(domainVOLERefresh))
	xof.Write(combinedSeed[:])
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(aliceID))
	xof.Write(buf[:])
	binary.BigEndian.PutUint32(buf[:], uint32(bobID))
	xof.Write(buf[:])
	return xof
}

// deriveFZeroSeed derives a new per-pair FZero seed from the combined refresh seed.
func deriveFZeroSeed(combinedSeed [16]byte, myID, peerID int) [16]byte {
	lo, hi := myID, peerID
	if lo > hi {
		lo, hi = hi, lo
	}
	xof := sha3.NewShake256()
	xof.Write([]byte(domainFZeroRefresh))
	xof.Write(combinedSeed[:])
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(lo))
	xof.Write(buf[:])
	binary.BigEndian.PutUint32(buf[:], uint32(hi))
	xof.Write(buf[:])
	var seed [16]byte
	xof.Read(seed[:])
	return seed
}
