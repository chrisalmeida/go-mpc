package frost

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"sort"

	"filippo.io/edwards25519"
)

// --- Feldman VSS Distributed Key Generation ---
//
// Implements the FROST KeyGen protocol of the FROST paper (Komlo-Goldberg,
// ePrint 2020/852, Figure 1), a Pedersen DKG hardened against rogue-key
// attacks by a Schnorr proof of knowledge of each party's constant term.
// RFC 9591 does not specify a DKG (Section 5: "This document does not
// specify how this information, including the signing key shares, are
// configured and distributed to participants").
//
// Each party Pi samples a degree-(t-1) polynomial fi(x) over the Ed25519
// scalar field and:
//   - Proves knowledge of a_{i,0}: σ_i = (R_i, μ_i) with k ← Z_q, R_i = k·B,
//     c_i = H(i, Φ, φ_{i,0}, R_i), μ_i = k + a_{i,0}·c_i (Round 1 step 2)
//   - Broadcasts Feldman commitments φ_{i,k} = a_{i,k}·B for k=0..t-1
//     together with σ_i (Round 1 steps 3-4)
//   - Commits (via hash commitment) to each other party's share
//   - Verifies every other party's σ_ℓ before sending any share
//     (Round 1 step 5: R_ℓ == μ_ℓ·B − c_ℓ·φ_{ℓ,0}, abort on failure)
//   - Verifies incoming shares against Feldman commitments (Round 2 step 2)
//
// The DKG produces shares compatible with FROST signing (RFC 9591).

// DKGPartyConfig holds per-party configuration for the DKG protocol.
type DKGPartyConfig struct {
	// MyID is this party's identifier (1-indexed, must be in AllIDs).
	MyID int
	// AllIDs is the sorted list of all party identifiers (1-indexed).
	AllIDs []int
	// Threshold t: the reconstruction threshold (minimum signers needed).
	Threshold int
	// Context is the context string Φ bound into each party's proof of
	// knowledge (FROST paper Figure 1, Round 1 step 2: "Φ being a context
	// string to prevent replay attacks"). All parties in a DKG session MUST
	// use the same value, and it SHOULD be unique per session (for example an
	// application identifier plus a fresh session identifier) so that a proof
	// captured in one session cannot be replayed in another. A proof made under
	// a different Context fails verification.
	Context []byte
}

// KeyShare holds a single participant's secret share and the group public key.
type KeyShare struct {
	// ID is the participant identifier (1-indexed).
	ID int
	// SecretShare is the participant's secret scalar s_i = f(i) (32 bytes LE).
	SecretShare []byte
	// PublicKey is the group verification key (32-byte compressed Edwards point).
	PublicKey []byte
	// VerificationShare is s_i * B (32-byte compressed Edwards point).
	VerificationShare []byte
	// GroupCommitments are the aggregated Feldman VSS commitments A_0, ..., A_{t-1}.
	// A_0 is the group public key.
	GroupCommitments [][]byte
	// Threshold is the signing threshold t.
	Threshold int
	// AllIDs lists all participant identifiers.
	AllIDs []int
}

// DKGRound1Output is what Pi broadcasts after DKG round 1: the Feldman
// commitment vector C_i and the proof of knowledge σ_i = (R_i, μ_i)
// (FROST paper Figure 1, Round 1 step 4).
type DKGRound1Output struct {
	// FeldmanCommitments are the t compressed Edwards points A_{i,0}...A_{i,t-1} (32 bytes each).
	FeldmanCommitments [][]byte
	// PairwiseCommitments[j] is the hash commitment to pi(j) sent to Pj.
	PairwiseCommitments map[int][32]byte
	// PairwiseSalts[j] is the salt used for the commitment to Pj's share.
	PairwiseSalts map[int][SaltLen]byte
	// ProofR is R_i = k·B, the commitment of the Schnorr proof of knowledge
	// of a_{i,0} (32-byte compressed Edwards point).
	ProofR []byte
	// ProofMu is μ_i = k + a_{i,0}·c_i, the response of the proof of knowledge
	// (32-byte little-endian scalar).
	ProofMu []byte
}

// DKGRound2Output contains the decommitted shares Pi sends after receiving all round 1 messages.
type DKGRound2Output struct {
	// SecretShares[j] is the 32-byte little-endian encoding of pi(j) sent to party Pj.
	SecretShares map[int][]byte
}

// validatePartyIDs checks that all IDs are positive, within bounds, and unique.
func validatePartyIDs(ids []int, phase string) error {
	seen := make(map[int]bool, len(ids))
	for _, id := range ids {
		if id <= 0 || id > maxPartyID {
			return &InvalidInputError{Phase: phase, Detail: fmt.Sprintf("party ID %d out of range [1, %d]", id, maxPartyID)}
		}
		if seen[id] {
			return &InvalidInputError{Phase: phase, Detail: fmt.Sprintf("duplicate party ID %d", id)}
		}
		seen[id] = true
	}
	return nil
}

// commit creates a hash commitment to msg using a freshly sampled random salt.
// commitment = SHA-256(msg || salt), where salt is SaltLen random bytes.
func commit(msg []byte) (com [32]byte, salt [SaltLen]byte, err error) {
	if _, err = rand.Read(salt[:]); err != nil {
		return
	}
	h := sha256.New()
	h.Write(msg)
	h.Write(salt[:])
	copy(com[:], h.Sum(nil))
	return
}

// openCommitment verifies a hash commitment in constant time.
func openCommitment(msg []byte, com [32]byte, salt [SaltLen]byte) error {
	h := sha256.New()
	h.Write(msg)
	h.Write(salt[:])
	expected := h.Sum(nil)
	if subtle.ConstantTimeCompare(expected, com[:]) != 1 {
		return fmt.Errorf("frost: commitment verification failed")
	}
	return nil
}

// sampleScalar samples a uniformly random scalar from the Ed25519 field.
// The probability of sampling zero is ~2^{-252}, which is negligible.
func sampleScalar() (*edwards25519.Scalar, error) {
	var buf [64]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return nil, err
	}
	s, err := edwards25519.NewScalar().SetUniformBytes(buf[:])
	if err != nil {
		return nil, err
	}
	return s, nil
}

// evalPoly evaluates the polynomial f(x) = coeffs[0] + coeffs[1]*x + ... + coeffs[t-1]*x^{t-1} at x.
func evalPoly(coeffs []*edwards25519.Scalar, x int) *edwards25519.Scalar {
	xScalar := scalarFromInt(x)
	result := edwards25519.NewScalar()
	xPow := scalarFromUint64(1) // x^0 = 1

	for _, c := range coeffs {
		term := edwards25519.NewScalar().Multiply(c, xPow)
		result.Add(result, term)
		xPow = edwards25519.NewScalar().Multiply(xPow, xScalar)
	}
	return result
}

// lagrangeCoeff computes the Lagrange basis coefficient for party myID evaluating at x=0,
// over the Ed25519 scalar field, with the given set of party IDs.
//
// lagrange(myID, allIDs, 0) = prod_{j≠myID} (-j / (myID - j)) mod L
func lagrangeCoeff(myID int, allIDs []int) *edwards25519.Scalar {
	num := scalarFromUint64(1)
	den := scalarFromUint64(1)
	xI := scalarFromInt(myID)
	zero := edwards25519.NewScalar()

	for _, j := range allIDs {
		if j == myID {
			continue
		}
		xJ := scalarFromInt(j)
		// num *= (0 - xJ) = -xJ
		negXJ := edwards25519.NewScalar().Subtract(zero, xJ)
		num = edwards25519.NewScalar().Multiply(num, negXJ)
		// den *= (xI - xJ)
		diff := edwards25519.NewScalar().Subtract(xI, xJ)
		den = edwards25519.NewScalar().Multiply(den, diff)
	}

	denInv := scalarInverse(den)
	return edwards25519.NewScalar().Multiply(num, denInv)
}

// dkgProveKnowledge computes σ_i = (R_i, μ_i), the Schnorr proof of knowledge
// of the constant term a_{i,0} (FROST paper Figure 1, Round 1 step 2):
//
//	R_i = k·B,  c_i = H(i, Φ, φ_{i,0}, R_i),  μ_i = k + a_{i,0}·c_i
//
// with H instantiated by hashDKGProof and Φ = context. k is the proof nonce
// sampled by the caller; it is zeroized before returning because, exactly like
// a signing nonce, k together with μ_i reveals a_{i,0}. Returns the 32-byte
// encodings of R_i and μ_i.
func dkgProveKnowledge(id int, context []byte, a0, k *edwards25519.Scalar) (proofR, proofMu []byte) {
	proofR = edwards25519.NewGeneratorPoint().ScalarBaseMult(k).Bytes()
	phi0 := edwards25519.NewGeneratorPoint().ScalarBaseMult(a0).Bytes()
	c := hashDKGProof(id, context, phi0, proofR)
	// μ = a0·c + k
	mu := edwards25519.NewScalar().MultiplyAdd(a0, c, k)
	proofMu = mu.Bytes()
	k.Set(edwards25519.NewScalar())
	mu.Set(edwards25519.NewScalar()) // μ is public, but it was derived from k; clear it too.
	return proofR, proofMu
}

// dkgVerifyKnowledge verifies party id's proof of knowledge σ = (R, μ) of the
// discrete log of its constant-term commitment φ_0 = r1.FeldmanCommitments[0]
// (FROST paper Figure 1, Round 1 step 5):
//
//	c = H(id, Φ, φ_0, R),  accept iff R == μ·B − c·φ_0
//
// φ_0 and R are parsed with deserializeElement (RFC 9591 Section 6.1) and μ
// must be a canonical scalar; any parse failure is a verification failure.
func dkgVerifyKnowledge(id int, context []byte, r1 *DKGRound1Output) error {
	if len(r1.FeldmanCommitments) == 0 {
		return fmt.Errorf("frost: party %d sent no constant-term commitment", id)
	}
	phi0Bytes := r1.FeldmanCommitments[0]
	phi0, err := deserializeElement(phi0Bytes)
	if err != nil {
		return fmt.Errorf("frost: party %d constant-term commitment: %w", id, err)
	}
	R, err := deserializeElement(r1.ProofR)
	if err != nil {
		return fmt.Errorf("frost: party %d proof commitment R: %w", id, err)
	}
	mu, err := edwards25519.NewScalar().SetCanonicalBytes(r1.ProofMu)
	if err != nil {
		return fmt.Errorf("frost: party %d proof response μ: %w", id, err)
	}
	c := hashDKGProof(id, context, phi0Bytes, r1.ProofR)

	// expected = μ·B − c·φ_0
	expected := edwards25519.NewGeneratorPoint().ScalarBaseMult(mu)
	cPhi0 := edwards25519.NewIdentityPoint().ScalarMult(c, phi0)
	expected.Subtract(expected, cPhi0)
	if expected.Equal(R) != 1 {
		return fmt.Errorf("frost: party %d proof of knowledge of a_0 does not verify", id)
	}
	return nil
}

// verifyRound1Proofs checks the round 1 message of every party other than
// config.MyID: it must be present, carry exactly t Feldman commitments that
// all pass deserializeElement, and its proof of knowledge must verify under
// config.Context. Returns the IDs of all parties failing any check, in
// config.AllIDs order.
func verifyRound1Proofs(config DKGPartyConfig, allRound1 map[int]*DKGRound1Output) []int {
	var bad []int
	for _, j := range config.AllIDs {
		if j == config.MyID {
			continue
		}
		r1 := allRound1[j]
		if r1 == nil || len(r1.FeldmanCommitments) != config.Threshold {
			bad = append(bad, j)
			continue
		}
		if _, err := parseFeldmanCommitments(r1.FeldmanCommitments); err != nil {
			bad = append(bad, j)
			continue
		}
		if err := dkgVerifyKnowledge(j, config.Context, r1); err != nil {
			bad = append(bad, j)
		}
	}
	return bad
}

// DKGRound1 executes the first round of the DKG for party config.MyID
// (FROST paper Figure 1, Round 1 steps 1-4). Pi samples a degree-(t-1)
// polynomial, proves knowledge of its constant term a_{i,0} under
// config.Context, computes the Feldman commitments, and commits (via hash
// commitment) to each other party's share. The returned DKGRound1Output is
// broadcast to all parties; the polynomial coefficients are secret and are
// needed by DKGRound2 and DKGFinalize.
func DKGRound1(config DKGPartyConfig) (*DKGRound1Output, []*edwards25519.Scalar, error) {
	if err := validatePartyIDs(config.AllIDs, "DKGRound1"); err != nil {
		return nil, nil, err
	}
	if config.Threshold <= 0 {
		return nil, nil, &InvalidInputError{Phase: "DKGRound1", Detail: "threshold must be positive"}
	}
	if config.Threshold > len(config.AllIDs) {
		return nil, nil, &InvalidInputError{Phase: "DKGRound1", Detail: fmt.Sprintf("threshold %d exceeds party count %d", config.Threshold, len(config.AllIDs))}
	}
	found := false
	for _, id := range config.AllIDs {
		if id == config.MyID {
			found = true
			break
		}
	}
	if !found {
		return nil, nil, &InvalidInputError{Phase: "DKGRound1", Detail: fmt.Sprintf("myID %d not in AllIDs", config.MyID)}
	}
	t := config.Threshold

	// Sample polynomial coefficients a_{i,0}, ..., a_{i,t-1}.
	coeffs := make([]*edwards25519.Scalar, t)
	for k := 0; k < t; k++ {
		c, err := sampleScalar()
		if err != nil {
			return nil, nil, fmt.Errorf("frost DKGRound1: sample coefficient: %w", err)
		}
		coeffs[k] = c
	}

	// Round 1 step 2: proof of knowledge of a_{i,0}. The nonce k is zeroized
	// inside dkgProveKnowledge.
	k, err := sampleScalar()
	if err != nil {
		return nil, nil, fmt.Errorf("frost DKGRound1: sample proof nonce: %w", err)
	}
	proofR, proofMu := dkgProveKnowledge(config.MyID, config.Context, coeffs[0], k)

	// Round 1 step 3: Feldman commitments φ_{i,k} = a_{i,k} * B.
	feldman := make([][]byte, t)
	for k := 0; k < t; k++ {
		pt := edwards25519.NewGeneratorPoint().ScalarBaseMult(coeffs[k])
		feldman[k] = pt.Bytes()
	}

	// Commit to pi(j) for each other party j.
	pairwiseComs := make(map[int][32]byte)
	pairwiseSalts := make(map[int][SaltLen]byte)
	for _, j := range config.AllIDs {
		if j == config.MyID {
			continue
		}
		share := evalPoly(coeffs, j)
		shareBytes := share.Bytes()

		com, salt, err := commit(shareBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("frost DKGRound1: commit share for %d: %w", j, err)
		}
		pairwiseComs[j] = com
		pairwiseSalts[j] = salt
	}

	out := &DKGRound1Output{
		FeldmanCommitments:  feldman,
		PairwiseCommitments: pairwiseComs,
		PairwiseSalts:       pairwiseSalts,
		ProofR:              proofR,
		ProofMu:             proofMu,
	}
	return out, coeffs, nil
}

// DKGRound2 verifies every other party's round 1 proof of knowledge and, only
// if all of them verify, decommits the pairwise shares (FROST paper Figure 1,
// Round 1 step 5 and Round 2 step 1). myCoeffs are the polynomial coefficients
// returned by DKGRound1; allRound1 maps party ID to the DKGRound1Output that
// party broadcast (this party's own entry is not required and is ignored).
//
// A missing or malformed round 1 message, or a proof that fails to verify
// under config.Context, aborts with a CheatingPartyError naming every
// offending party. No share is released in that case: this is what prevents
// the rogue-key attack, in which a party publishes a constant-term commitment
// whose discrete log it does not know (for example Y − Σ_{ℓ≠i} φ_{ℓ,0} for a
// Y of its choosing) and would otherwise still receive honest shares.
//
// Returns the decommitments (plaintext shares) to send to each other party.
func DKGRound2(config DKGPartyConfig, myCoeffs []*edwards25519.Scalar, allRound1 map[int]*DKGRound1Output) (*DKGRound2Output, error) {
	if config.Threshold <= 0 || len(myCoeffs) != config.Threshold {
		return nil, &InvalidInputError{Phase: "DKGRound2", Detail: fmt.Sprintf("expected %d polynomial coefficients, got %d", config.Threshold, len(myCoeffs))}
	}
	if bad := verifyRound1Proofs(config, allRound1); len(bad) > 0 {
		return nil, &CheatingPartyError{PartyIDs: bad, Phase: "DKGRound2", Detail: "round 1 proof of knowledge missing or invalid"}
	}

	secretShares := make(map[int][]byte)
	for _, j := range config.AllIDs {
		if j == config.MyID {
			continue
		}
		share := evalPoly(myCoeffs, j)
		shareBytes := make([]byte, ScalarLen)
		copy(shareBytes, share.Bytes())
		secretShares[j] = shareBytes
	}
	return &DKGRound2Output{SecretShares: secretShares}, nil
}

// parseFeldmanCommitments deserializes a received Feldman commitment vector
// with deserializeElement (RFC 9591 Section 6.1), rejecting non-canonical
// encodings, the identity, and points outside the prime-order subgroup.
func parseFeldmanCommitments(commitments [][]byte) ([]*edwards25519.Point, error) {
	points := make([]*edwards25519.Point, len(commitments))
	for k, c := range commitments {
		pt, err := deserializeElement(c)
		if err != nil {
			return nil, fmt.Errorf("frost: parse Feldman commitment [%d]: %w", k, err)
		}
		points[k] = pt
	}
	return points, nil
}

// feldmanVerify checks that share·B == sum_{k=0}^{t-1} A_{i,k} * x^k.
// This is the standard Feldman VSS verification equation.
func feldmanVerify(share *edwards25519.Scalar, x int, feldmanCommitments []*edwards25519.Point) error {
	xScalar := scalarFromInt(x)
	xPow := scalarFromUint64(1)

	// Compute RHS = sum_{k=0}^{t-1} A_{i,k} * x^k.
	rhs := edwards25519.NewIdentityPoint()
	for _, Aik := range feldmanCommitments {
		scaled := edwards25519.NewIdentityPoint().ScalarMult(xPow, Aik)
		rhs.Add(rhs, scaled)
		xPow = edwards25519.NewScalar().Multiply(xPow, xScalar)
	}

	// Compute LHS = share * B.
	lhs := edwards25519.NewGeneratorPoint().ScalarBaseMult(share)

	if lhs.Equal(rhs) != 1 {
		return fmt.Errorf("frost: Feldman verification failed: share inconsistent with commitments")
	}
	return nil
}

// DKGFinalize verifies all received round 1 and round 2 messages and computes
// the final key share (FROST paper Figure 1, Round 2 steps 2-4). For each
// other party j it:
//  1. Re-verifies the proof of knowledge σ_j of a_{j,0} under config.Context
//     (Round 1 step 5), so a party that skipped DKGRound2's check still aborts.
//  2. Verifies the hash commitment: Open(pi_j(myID), com_{j,myID}, salt_{j,myID}).
//  3. Verifies the Feldman check: pi_j(myID)·B == sum_k A_{j,k}·myID^k.
//
// This party's own contribution is taken from myCoeffs, so allRound1 need not
// contain its own entry. Returns the final KeyShare, or a CheatingPartyError
// listing every party whose messages failed verification.
func DKGFinalize(
	config DKGPartyConfig,
	myCoeffs []*edwards25519.Scalar,
	allRound1 map[int]*DKGRound1Output,
	allRound2 map[int]*DKGRound2Output,
) (*KeyShare, error) {
	if config.Threshold <= 0 || len(myCoeffs) != config.Threshold {
		return nil, &InvalidInputError{Phase: "DKGFinalize", Detail: fmt.Sprintf("expected %d polynomial coefficients, got %d", config.Threshold, len(myCoeffs))}
	}

	var badSenders []int
	finalShare := edwards25519.NewScalar()
	// feldmanPoints[j] is party j's verified commitment vector φ_{j,0..t-1}.
	feldmanPoints := make(map[int][]*edwards25519.Point, len(config.AllIDs))

	for _, j := range config.AllIDs {
		if j == config.MyID {
			// My own share: evaluate my polynomial at myID; my own commitments
			// are recomputed from my coefficients.
			myShare := evalPoly(myCoeffs, config.MyID)
			finalShare.Add(finalShare, myShare)
			mine := make([]*edwards25519.Point, len(myCoeffs))
			for k, c := range myCoeffs {
				mine[k] = edwards25519.NewGeneratorPoint().ScalarBaseMult(c)
			}
			feldmanPoints[j] = mine
			continue
		}

		r1j := allRound1[j]
		r2j := allRound2[j]
		if r1j == nil || r2j == nil {
			badSenders = append(badSenders, j)
			continue
		}

		// Verify Feldman commitment count matches threshold.
		if len(r1j.FeldmanCommitments) != config.Threshold {
			badSenders = append(badSenders, j)
			continue
		}

		// Step 1: re-verify the proof of knowledge of a_{j,0}.
		if err := dkgVerifyKnowledge(j, config.Context, r1j); err != nil {
			badSenders = append(badSenders, j)
			continue
		}
		points, err := parseFeldmanCommitments(r1j.FeldmanCommitments)
		if err != nil {
			badSenders = append(badSenders, j)
			continue
		}

		// Get the share pj(myID) sent by party j.
		shareBytes := r2j.SecretShares[config.MyID]
		if len(shareBytes) != ScalarLen {
			badSenders = append(badSenders, j)
			continue
		}
		shareVal, err := edwards25519.NewScalar().SetCanonicalBytes(shareBytes)
		if err != nil {
			badSenders = append(badSenders, j)
			continue
		}

		// Step 2: verify hash commitment.
		com, ok1 := r1j.PairwiseCommitments[config.MyID]
		salt, ok2 := r1j.PairwiseSalts[config.MyID]
		if !ok1 || !ok2 {
			badSenders = append(badSenders, j)
			continue
		}
		if err := openCommitment(shareBytes, com, salt); err != nil {
			badSenders = append(badSenders, j)
			continue
		}

		// Step 3: verify Feldman check: pj(myID)·B == sum_k A_{j,k}·myID^k.
		if err := feldmanVerify(shareVal, config.MyID, points); err != nil {
			badSenders = append(badSenders, j)
			continue
		}

		finalShare.Add(finalShare, shareVal)
		feldmanPoints[j] = points
	}

	if len(badSenders) > 0 {
		return nil, &CheatingPartyError{PartyIDs: badSenders, Phase: "DKGFinalize", Detail: "proof of knowledge, share, or Feldman verification failed"}
	}

	// Compute aggregated Feldman commitments: A_k = sum_j A_{j,k} for each coefficient index.
	t := config.Threshold
	groupCommitments := make([][]byte, t)
	for k := 0; k < t; k++ {
		sumPt := edwards25519.NewIdentityPoint()
		for _, j := range config.AllIDs {
			sumPt.Add(sumPt, feldmanPoints[j][k])
		}
		groupCommitments[k] = sumPt.Bytes()
	}

	// Group public key is A_0 = sum_j A_{j,0}.
	publicKey := groupCommitments[0]

	// Verification share: s_i * B.
	verificationShare := edwards25519.NewGeneratorPoint().ScalarBaseMult(finalShare).Bytes()

	// Sort AllIDs for deterministic output.
	allIDsSorted := make([]int, len(config.AllIDs))
	copy(allIDsSorted, config.AllIDs)
	sort.Ints(allIDsSorted)

	ks := &KeyShare{
		ID:                config.MyID,
		SecretShare:       finalShare.Bytes(),
		PublicKey:         publicKey,
		VerificationShare: verificationShare,
		GroupCommitments:  groupCommitments,
		Threshold:         config.Threshold,
		AllIDs:            allIDsSorted,
	}
	return ks, nil
}
