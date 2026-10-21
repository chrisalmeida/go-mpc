package frost

// Proactive share refresh for FROST Ed25519.
//
// # Protocol summary (all parties online, distributed — no trusted dealer)
//
// Each party Pi samples a zero-constant degree-(t-1) polynomial:
//
//	f_i(x) = δ_{i,1}·x + δ_{i,2}·x² + … + δ_{i,t-1}·x^{t-1}
//
// so f_i(0) = 0.  Each Pj receives f_i(j) from Pi via commit-then-reveal
// and verifies consistency with Feldman commitments {C_{i,k} = δ_{i,k}·B}.
//
// New Shamir share for Pj:
//
//	share_j' = share_j + Σ_i f_i(j)  mod L
//
// Secret preserved: Lagrange(share', 0) = Lagrange(share, 0) since Σ_i f_i(0) = 0.
//
// Unlike dkls23 refresh, there is no VOLE/OT/FZero state to re-randomize.
// The refresh only updates Shamir shares, verification shares, and group
// commitments.

import (
	"crypto/rand"
	"fmt"

	"filippo.io/edwards25519"
)

// refreshContribution identifies an applied local contribution using existing
// public values. It is bookkeeping, not a protocol message or hash input.
type refreshContribution struct {
	publicKey string
	partyID   int
	seed      [16]byte
}

// RefreshRound1Output is broadcast by each party Pi in refresh round 1.
type RefreshRound1Output struct {
	// FeldmanCommitments are the t-1 compressed Edwards points C_{i,k} = δ_{i,k}·B
	// for k = 1..t-1. No k=0 term: the polynomial is zero-constant, so f_i(0)=0.
	FeldmanCommitments [][]byte
	// PairwiseCommitments[j] is the hash commitment to f_i(j) for peer j.
	PairwiseCommitments map[int][32]byte
	// PairwiseSalts[j] is the salt used for the commitment to f_i(j).
	PairwiseSalts map[int][SaltLen]byte
	// SeedCommitment is the hash commitment to this party's 16-byte seed contribution.
	SeedCommitment [32]byte
	// SeedSalt is the salt for the seed commitment.
	SeedSalt [SaltLen]byte
}

// RefreshRound2Output contains the decommitments Pi broadcasts in refresh round 2.
type RefreshRound2Output struct {
	// SecretShares[j] is f_i(j) encoded as 32-byte little-endian for each peer j.
	SecretShares map[int][]byte
	// Seed is the 16-byte seed Pi contributed in round 1.
	Seed [16]byte
}

// evalZeroConstPoly evaluates the zero-constant polynomial
//
//	f(x) = coeffs[0]·x + coeffs[1]·x² + … + coeffs[t-2]·x^{t-1}
//
// at x. The polynomial has no constant term, so f(0) = 0.
func evalZeroConstPoly(coeffs []*edwards25519.Scalar, x int) *edwards25519.Scalar {
	xScalar := scalarFromInt(x)
	xPow := edwards25519.NewScalar().Set(xScalar) // x^1
	result := edwards25519.NewScalar()

	for _, c := range coeffs {
		term := edwards25519.NewScalar().Multiply(c, xPow)
		result.Add(result, term)
		xPow = edwards25519.NewScalar().Multiply(xPow, xScalar)
	}
	return result
}

// refreshFeldmanVerify checks that share·B = Σ_{k=1}^{t-1} C_{i,k} · x^k
// for a zero-constant polynomial (no constant term commitment). The received
// commitments are parsed with deserializeElement (RFC 9591 Section 6.1).
func refreshFeldmanVerify(share *edwards25519.Scalar, x int, nonConstFeldman [][]byte) error {
	if len(nonConstFeldman) == 0 {
		// t = 1: the zero-constant polynomial is f(x) = 0 for all x.
		zero := edwards25519.NewScalar()
		if share.Equal(zero) != 1 {
			return fmt.Errorf("frost: refresh Feldman failed: nonzero share for zero-degree polynomial")
		}
		return nil
	}

	xScalar := scalarFromInt(x)
	xPow := edwards25519.NewScalar().Set(xScalar) // x^1

	// RHS = Σ_{k=1}^{t-1} C_{i,k} · x^k.
	rhs := edwards25519.NewIdentityPoint()
	for _, commitBytes := range nonConstFeldman {
		Cik, err := deserializeElement(commitBytes)
		if err != nil {
			return fmt.Errorf("frost: parse refresh Feldman commitment: %w", err)
		}
		scaled := edwards25519.NewIdentityPoint().ScalarMult(xPow, Cik)
		rhs.Add(rhs, scaled)
		xPow = edwards25519.NewScalar().Multiply(xPow, xScalar)
	}

	// LHS = share · B.
	lhs := edwards25519.NewGeneratorPoint().ScalarBaseMult(share)

	if lhs.Equal(rhs) != 1 {
		return fmt.Errorf("frost: refresh Feldman verification failed: share inconsistent with commitments")
	}
	return nil
}

// RefreshRound1 executes round 1 of the proactive refresh protocol.
//
// Pi samples a zero-constant polynomial f_i(x) = δ_1·x + … + δ_{t-1}·x^{t-1},
// broadcasts Feldman commitments C_{i,k} = δ_k·B for k = 1..t-1, commits to
// f_i(j) for each peer j, and commits to a fresh 16-byte seed.
//
// Returns the broadcast output, the polynomial coefficients (kept private until
// round 2), and the seed (kept private until round 2).
func RefreshRound1(signer *SignerState) (*RefreshRound1Output, []*edwards25519.Scalar, [16]byte, error) {
	signer.mu.RLock()
	defer signer.mu.RUnlock()

	if err := checkBlacklist(signer, signer.KeyShare.AllIDs, "RefreshRound1"); err != nil {
		return nil, nil, [16]byte{}, err
	}

	t := signer.KeyShare.Threshold
	myID := signer.KeyShare.ID

	// Sample t-1 coefficients δ_1, …, δ_{t-1} for the zero-constant polynomial.
	coeffs := make([]*edwards25519.Scalar, t-1)
	for k := 0; k < t-1; k++ {
		c, err := sampleScalar()
		if err != nil {
			return nil, nil, [16]byte{}, fmt.Errorf("frost RefreshRound1: sample coeff %d: %w", k+1, err)
		}
		coeffs[k] = c
	}

	// Compute Feldman commitments C_{i,k} = δ_k · B for k = 1..t-1.
	feldman := make([][]byte, t-1)
	for k := 0; k < t-1; k++ {
		pt := edwards25519.NewGeneratorPoint().ScalarBaseMult(coeffs[k])
		feldman[k] = pt.Bytes()
	}

	// Commit to f_i(j) for each peer j.
	pairwiseComs := make(map[int][32]byte)
	pairwiseSalts := make(map[int][SaltLen]byte)
	for _, j := range signer.KeyShare.AllIDs {
		if j == myID {
			continue
		}
		share := evalZeroConstPoly(coeffs, j)
		shareBytes := share.Bytes()

		com, salt, err := commit(shareBytes)
		if err != nil {
			return nil, nil, [16]byte{}, fmt.Errorf("frost RefreshRound1: commit share for %d: %w", j, err)
		}
		pairwiseComs[j] = com
		pairwiseSalts[j] = salt
	}

	// Sample a fresh 16-byte seed and commit to it.
	var mySeed [16]byte
	if _, err := rand.Read(mySeed[:]); err != nil {
		return nil, nil, [16]byte{}, fmt.Errorf("frost RefreshRound1: sample seed: %w", err)
	}
	seedCom, seedSalt, err := commit(mySeed[:])
	if err != nil {
		return nil, nil, [16]byte{}, fmt.Errorf("frost RefreshRound1: commit seed: %w", err)
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
func RefreshRound2(signer *SignerState, coeffs []*edwards25519.Scalar, mySeed [16]byte) (*RefreshRound2Output, error) {
	signer.mu.RLock()
	defer signer.mu.RUnlock()

	secretShares := make(map[int][]byte)
	for _, j := range signer.KeyShare.AllIDs {
		if j == signer.KeyShare.ID {
			continue
		}
		share := evalZeroConstPoly(coeffs, j)
		shareBytes := make([]byte, ScalarLen)
		copy(shareBytes, share.Bytes())
		secretShares[j] = shareBytes
	}
	return &RefreshRound2Output{SecretShares: secretShares, Seed: mySeed}, nil
}

// RefreshFinalize verifies all received round 1/2 messages and, if all checks
// pass, mutates the signer's state:
//
//  1. Verifies hash commitment of f_j(myID) for each sender j.
//  2. Verifies Feldman consistency: f_j(myID)·B = Σ_{k=1}^{t-1} C_{j,k}·myID^k.
//  3. Verifies seed hash commitment.
//  4. Updates the Shamir share: share += Σ_j f_j(myID) mod L.
//  5. Updates the verification share: new_share · B.
//  6. Increments signer.Epoch.
//
// The group public key and group commitments A_0 are unchanged (since Σ f_i(0) = 0).
// Returns an error naming all bad senders if any verification fails; state is
// NOT modified in that case.
// A completed local seed contribution cannot be applied again on this signer.
// This in-memory replay record does not replace durable caller-side routing
// and replay protection after state restoration.
func RefreshFinalize(
	signer *SignerState,
	coeffs []*edwards25519.Scalar,
	mySeed [16]byte,
	allRound1 map[int]*RefreshRound1Output,
	allRound2 map[int]*RefreshRound2Output,
) error {
	signer.mu.Lock()
	defer signer.mu.Unlock()

	if err := checkBlacklist(signer, signer.KeyShare.AllIDs, "RefreshFinalize"); err != nil {
		return err
	}
	contribution := refreshContribution{publicKey: string(signer.KeyShare.PublicKey), partyID: signer.KeyShare.ID, seed: mySeed}
	if signer.completedRefresh[contribution] {
		return &CorruptStateError{Phase: "RefreshFinalize", Detail: "local refresh contribution already applied"}
	}

	myID := signer.KeyShare.ID
	t := signer.KeyShare.Threshold
	var badSenders []int

	// Validate messages and accumulate share additions from peers.
	type peerContrib struct {
		shareVal *edwards25519.Scalar
		seed     [16]byte
	}
	peerContribs := make(map[int]peerContrib)

	for _, j := range signer.KeyShare.AllIDs {
		if j == myID {
			continue
		}
		r1j := allRound1[j]
		r2j := allRound2[j]
		if r1j == nil || r2j == nil {
			badSenders = append(badSenders, j)
			continue
		}

		// Verify commitment count matches t-1.
		if len(r1j.FeldmanCommitments) != t-1 {
			badSenders = append(badSenders, j)
			continue
		}

		// Step 1: Verify hash commitment of f_j(myID).
		shareBytes := r2j.SecretShares[myID]
		if len(shareBytes) != ScalarLen {
			badSenders = append(badSenders, j)
			continue
		}
		com, ok1 := r1j.PairwiseCommitments[myID]
		salt, ok2 := r1j.PairwiseSalts[myID]
		if !ok1 || !ok2 {
			badSenders = append(badSenders, j)
			continue
		}
		if err := openCommitment(shareBytes, com, salt); err != nil {
			badSenders = append(badSenders, j)
			continue
		}

		shareVal, err := edwards25519.NewScalar().SetCanonicalBytes(shareBytes)
		if err != nil {
			badSenders = append(badSenders, j)
			continue
		}

		// Step 2: Feldman verification for zero-constant polynomial.
		if err := refreshFeldmanVerify(shareVal, myID, r1j.FeldmanCommitments); err != nil {
			badSenders = append(badSenders, j)
			continue
		}

		// Step 3: Verify seed hash commitment.
		if err := openCommitment(r2j.Seed[:], r1j.SeedCommitment, r1j.SeedSalt); err != nil {
			badSenders = append(badSenders, j)
			continue
		}

		peerContribs[j] = peerContrib{shareVal: shareVal, seed: r2j.Seed}
	}

	if len(badSenders) > 0 {
		return &CheatingPartyError{PartyIDs: badSenders, Phase: "RefreshFinalize", Detail: "share, Feldman, or seed verification failed"}
	}

	// Step 4: Update Shamir share.
	// new_share = old_share + f_i(myID) + Σ_{j≠i} f_j(myID) mod L.
	oldShare, err := edwards25519.NewScalar().SetCanonicalBytes(signer.KeyShare.SecretShare)
	if err != nil {
		return &CorruptStateError{Phase: "RefreshFinalize", Detail: "invalid current secret share"}
	}

	myContrib := evalZeroConstPoly(coeffs, myID)
	shareAdd := edwards25519.NewScalar().Set(myContrib)
	for _, j := range signer.KeyShare.AllIDs {
		if j == myID {
			continue
		}
		pc := peerContribs[j]
		shareAdd.Add(shareAdd, pc.shareVal)
	}

	newShare := edwards25519.NewScalar().Add(oldShare, shareAdd)

	// Step 5: Update verification share.
	newVerificationShare := edwards25519.NewGeneratorPoint().ScalarBaseMult(newShare).Bytes()

	// All mutations succeed atomically from this point.
	signer.KeyShare.SecretShare = newShare.Bytes()
	signer.KeyShare.VerificationShare = newVerificationShare
	signer.Epoch++
	if signer.completedRefresh == nil {
		signer.completedRefresh = make(map[refreshContribution]bool)
	}
	signer.completedRefresh[contribution] = true
	return nil
}
