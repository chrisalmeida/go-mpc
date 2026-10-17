package dkls23

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
)

// lagrangeCoeff computes the Lagrange basis coefficient for party myID evaluating at x=0,
// over the field Zq, with the given set of party IDs.
//
// lagrange(myID, allIDs, 0) = prod_{j≠myID} (-j / (myID - j)) mod q
//
// This is used in DKG finalization and signing to reconstruct the secret
// from Shamir shares without actually computing the secret (only combined scalar multiplications).
// All arithmetic is constant-time via ModNScalar.
func lagrangeCoeff(myID int, allIDs []int) btcec.ModNScalar {
	var num, den btcec.ModNScalar
	num.SetInt(1)
	den.SetInt(1)
	var xI btcec.ModNScalar
	xI.SetInt(uint32(myID))
	for _, j := range allIDs {
		if j == myID {
			continue
		}
		var xJ btcec.ModNScalar
		xJ.SetInt(uint32(j))
		// num *= -xJ
		var negXJ btcec.ModNScalar
		negXJ.NegateVal(&xJ)
		num.Mul(&negXJ)
		// den *= (xI - xJ)
		var diff btcec.ModNScalar
		diff.NegateVal(&xJ)
		diff.Add(&xI)
		den.Mul(&diff)
	}
	// coeff = num * den^{-1} mod q
	denInv := scalarInverse(&den)
	var coeff btcec.ModNScalar
	coeff.Mul2(&num, &denInv)
	return coeff
}

// maxPartyID is the upper bound for party identifiers. IDs are stored in
// uint32 fields inside ModNScalar, so we cap well below 2^32 to prevent
// overflow in Lagrange coefficient arithmetic.
const maxPartyID = 1<<31 - 1

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

// --- πRelaxedKeyGen: Feldman VSS based DKG for secp256k1, t-of-n ---
// Paper Protocol 7.1.
//
// Each party Pi samples a degree-(t-1) polynomial p_i(x) over Zq and
// (step 2) COMMITS, via FCom, both to the vector of Feldman commitments
// {C_{i,k} = a_{i,k}·G} and to each pairwise evaluation p_i(j). Only after
// being notified of every other party's commitments (step 3) does Pi
// decommit them. Each Pj then (step 4) verifies the decommitments and that
// p_i(j)·G is consistent with the committed polynomial.
//
// The paper commits to the point evaluations {P_i(j)}_{j∈[0,t-1]}; this
// implementation commits to the coefficient points {C_{i,k}}_{k∈[0,t-1]}.
// Both are encodings of the same degree-(t-1) polynomial in G, and the
// step-4 interpolation check is equivalent to the Feldman equation
// p_j(i)·G = Σ_k C_{j,k}·i^k.
//
// Steps 4-5 of the paper also require every party to send (ok, sid) or
// (abort, sid) after verification and to abort if any party aborts. That
// echo round is transport-level: callers must exchange the outcome of
// DKGFinalize and discard the key pair if any party reports an error.

// DKGPartyConfig holds per-party configuration for the DKG protocol.
type DKGPartyConfig struct {
	// MyID is this party's identifier (1-indexed, must be in AllIDs).
	MyID int
	// AllIDs is the sorted list of all party identifiers (1-indexed).
	AllIDs []int
	// Threshold t: the reconstruction threshold (minimum signers needed).
	Threshold int
}

// DKGRound1Output is what Pi broadcasts after DKG round 1 (paper step 2):
// FCom commitments only, nothing is revealed yet.
type DKGRound1Output struct {
	// FeldmanCommitment is FCom(n) of the concatenated Feldman commitments
	// C_{i,0} ‖ … ‖ C_{i,t-1} (33 bytes each).
	FeldmanCommitment [32]byte
	// PairwiseCommitments[j] is FCom(2) of p_i(j) for Pj.
	PairwiseCommitments map[int][32]byte
}

// DKGPrivateState is Pi's private DKG state between rounds. It must not be
// sent to anyone. Call Zero after DKGFinalize.
type DKGPrivateState struct {
	// Coeffs are the polynomial coefficients a_{i,0}, …, a_{i,t-1}.
	Coeffs []btcec.ModNScalar
	// FeldmanCommitments are the t compressed curve points C_{i,0}...C_{i,t-1}.
	FeldmanCommitments [][]byte
	// FeldmanSalt is the FCom salt for FeldmanCommitment.
	FeldmanSalt [SaltLen]byte
	// PairwiseSalts[j] is the FCom salt for the commitment to p_i(j).
	PairwiseSalts map[int][SaltLen]byte
}

// Zero zeroizes the secret polynomial coefficients.
func (s *DKGPrivateState) Zero() {
	if s == nil {
		return
	}
	for k := range s.Coeffs {
		s.Coeffs[k].Zero()
	}
}

// DKGRound2Output contains the decommitments Pi sends after being notified of
// all other parties' round 1 commitments (paper step 3).
type DKGRound2Output struct {
	// FeldmanCommitments are the t compressed curve points C_{i,0}...C_{i,t-1} (33 bytes each).
	FeldmanCommitments [][]byte
	// FeldmanSalt opens DKGRound1Output.FeldmanCommitment.
	FeldmanSalt [SaltLen]byte
	// SecretShares[j] is the 32-byte big-endian encoding of p_i(j) sent to party Pj.
	SecretShares map[int][]byte
	// PairwiseSalts[j] opens DKGRound1Output.PairwiseCommitments[j].
	PairwiseSalts map[int][SaltLen]byte
}

// evalPoly evaluates the polynomial with coefficients (coeffs[0]+coeffs[1]*x+...+coeffs[t-1]*x^{t-1}) at x.
// All arithmetic is constant-time via ModNScalar.
func evalPoly(coeffs []btcec.ModNScalar, x uint32) btcec.ModNScalar {
	var result, xScalar, xPow btcec.ModNScalar
	xScalar.SetInt(x)
	xPow.SetInt(1)
	for _, c := range coeffs {
		var term btcec.ModNScalar
		term.Mul2(&c, &xPow)
		result.Add(&term)
		xPow.Mul(&xScalar)
	}
	return result
}

// concatFeldman serializes the Feldman commitment vector for FCom.
func concatFeldman(points [][]byte) []byte {
	out := make([]byte, 0, len(points)*33)
	for _, p := range points {
		out = append(out, p...)
	}
	return out
}

// DKGRound1 executes the first round of the DKG for party config.MyID
// (paper Protocol 7.1 steps 1-2). Pi samples a degree-(t-1) polynomial and
// commits, via FCom, to its Feldman commitments and to each other party's share.
// Returns the round 1 commitments and the private state needed for round 2.
func DKGRound1(config DKGPartyConfig) (*DKGRound1Output, *DKGPrivateState, error) {
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

	// Sample polynomial coefficients a_{i,0}, ..., a_{i,t-1} ← Zq.
	coeffs := make([]btcec.ModNScalar, t)
	for k := 0; k < t; k++ {
		c, err := sampleScalar()
		if err != nil {
			return nil, nil, fmt.Errorf("dkls23 DKGRound1: sample coefficient: %w", err)
		}
		coeffs[k] = c
	}

	// Compute Feldman commitments C_{i,k} = a_{i,k} * G.
	feldman := make([][]byte, t)
	for k := 0; k < t; k++ {
		pt, err := scalarMulGCompressed(&coeffs[k])
		if err != nil {
			return nil, nil, fmt.Errorf("dkls23 DKGRound1: Feldman commitment: %w", err)
		}
		feldman[k] = pt
	}

	// FCom(n): commit to the Feldman commitment vector.
	feldmanCom, feldmanSalt, err := Commit(concatFeldman(feldman))
	if err != nil {
		return nil, nil, fmt.Errorf("dkls23 DKGRound1: commit Feldman commitments: %w", err)
	}

	// FCom(2): commit to p_i(j) for each other party j.
	pairwiseComs := make(map[int][32]byte)
	pairwiseSalts := make(map[int][SaltLen]byte)
	for _, j := range config.AllIDs {
		if j == config.MyID {
			continue
		}
		share := evalPoly(coeffs, uint32(j))
		shareArr := share.Bytes()
		shareBytes := shareArr[:]

		com, salt, err := Commit(shareBytes)
		share.Zero()
		for i := range shareArr {
			shareArr[i] = 0
		}
		if err != nil {
			return nil, nil, fmt.Errorf("dkls23 DKGRound1: commit share for %d: %w", j, err)
		}
		pairwiseComs[j] = com
		pairwiseSalts[j] = salt
	}

	out := &DKGRound1Output{
		FeldmanCommitment:   feldmanCom,
		PairwiseCommitments: pairwiseComs,
	}
	priv := &DKGPrivateState{
		Coeffs:             coeffs,
		FeldmanCommitments: feldman,
		FeldmanSalt:        feldmanSalt,
		PairwiseSalts:      pairwiseSalts,
	}
	return out, priv, nil
}

// DKGRound2 releases Pi's committed values (paper Protocol 7.1 step 3).
// It may only be called once Pi has been notified of all other parties'
// round 1 commitments, so theirRound1 must contain an entry for every
// other party in config.AllIDs.
// Returns the decommitments: the Feldman commitments with their salt, and the
// plaintext shares with their salts, to send to each other party.
func DKGRound2(config DKGPartyConfig, priv *DKGPrivateState, theirRound1 map[int]*DKGRound1Output) (*DKGRound2Output, error) {
	if priv == nil {
		return nil, &InvalidInputError{Phase: "DKGRound2", Detail: "missing private state"}
	}
	for _, j := range config.AllIDs {
		if j == config.MyID {
			continue
		}
		if theirRound1[j] == nil {
			return nil, &InvalidInputError{Phase: "DKGRound2", Detail: fmt.Sprintf("missing round 1 commitment from party %d", j)}
		}
	}

	secretShares := make(map[int][]byte)
	pairwiseSalts := make(map[int][SaltLen]byte)
	for _, j := range config.AllIDs {
		if j == config.MyID {
			continue
		}
		share := evalPoly(priv.Coeffs, uint32(j))
		shareArr := share.Bytes()
		shareBytes := make([]byte, 32)
		copy(shareBytes, shareArr[:])
		share.Zero()
		for i := range shareArr {
			shareArr[i] = 0
		}
		secretShares[j] = shareBytes
		pairwiseSalts[j] = priv.PairwiseSalts[j]
	}
	feldman := make([][]byte, len(priv.FeldmanCommitments))
	copy(feldman, priv.FeldmanCommitments)
	return &DKGRound2Output{
		FeldmanCommitments: feldman,
		FeldmanSalt:        priv.FeldmanSalt,
		SecretShares:       secretShares,
		PairwiseSalts:      pairwiseSalts,
	}, nil
}

// feldmanVerify checks that share·G == sum_{k=0}^{t-1} C_{i,k} * x^k.
// This is the standard Feldman VSS verification equation.
func feldmanVerify(share *btcec.ModNScalar, x int, feldmanCommitments [][]byte) error {
	t := len(feldmanCommitments)
	var xScalar, xPow btcec.ModNScalar
	xScalar.SetInt(uint32(x))
	xPow.SetInt(1)

	// Compute RHS = sum_{k=0}^{t-1} C_{i,k} * x^k (as EC points).
	var rhs btcec.JacobianPoint
	for k := 0; k < t; k++ {
		Cik, err := compressedToPoint(feldmanCommitments[k])
		if err != nil {
			return fmt.Errorf("dkls23: parse Feldman commitment: %w", err)
		}
		scaled := scalarMul(&xPow, Cik)
		btcec.AddNonConst(&rhs, scaled, &rhs)
		xPow.Mul(&xScalar)
	}
	rhs.ToAffine()

	// Compute LHS = share * G.
	var lhs btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(share, &lhs)
	lhs.ToAffine()

	if lhs.X.IsZero() && lhs.Y.IsZero() {
		return errors.New("dkls23: LHS is point at infinity")
	}
	if !lhs.X.Equals(&rhs.X) || !lhs.Y.Equals(&rhs.Y) {
		return errors.New("dkls23: Feldman verification failed: share inconsistent with commitments")
	}
	return nil
}

// DKGFinalize verifies all received decommitments and computes the final key
// share (paper Protocol 7.1 step 4). For each sender j:
//  1. Opens the FCom(n) commitment to j's Feldman commitments and checks that
//     exactly t points were committed.
//  2. Opens the FCom(2) commitment to p_j(myID).
//  3. Verifies the Feldman check: p_j(myID)·G == Σ_k C_{j,k}·myID^k.
//
// Returns the final share p(myID) = Σ_j p_j(myID) mod q and the master public
// key pk = Σ_j C_{j,0}. Returns an error listing bad senders if any check
// fails; the caller must then report (abort, sid) to all parties.
func DKGFinalize(
	config DKGPartyConfig,
	priv *DKGPrivateState,
	allRound1 map[int]*DKGRound1Output,
	allRound2 map[int]*DKGRound2Output,
) (share btcec.ModNScalar, publicKey []byte, err error) {
	if priv == nil {
		return btcec.ModNScalar{}, nil, &InvalidInputError{Phase: "DKGFinalize", Detail: "missing private state"}
	}
	var badSenders []int

	var finalShare btcec.ModNScalar
	feldmanByParty := make(map[int][][]byte, len(config.AllIDs))

	for _, j := range config.AllIDs {
		if j == config.MyID {
			// My own share: evaluate my polynomial at myID.
			myShare := evalPoly(priv.Coeffs, uint32(config.MyID))
			finalShare.Add(&myShare)
			myShare.Zero()
			feldmanByParty[j] = priv.FeldmanCommitments
			continue
		}

		r1j := allRound1[j]
		r2j := allRound2[j]
		if r1j == nil || r2j == nil {
			badSenders = append(badSenders, j)
			continue
		}

		// Step 1: Open FCom(n) of the Feldman commitments; exactly t points.
		if len(r2j.FeldmanCommitments) != config.Threshold {
			badSenders = append(badSenders, j)
			continue
		}
		if err2 := Open(concatFeldman(r2j.FeldmanCommitments), r1j.FeldmanCommitment, r2j.FeldmanSalt); err2 != nil {
			badSenders = append(badSenders, j)
			continue
		}

		// Step 2: Open FCom(2) of the share p_j(myID).
		shareBytes := r2j.SecretShares[config.MyID]
		if len(shareBytes) != 32 {
			badSenders = append(badSenders, j)
			continue
		}
		com, ok1 := r1j.PairwiseCommitments[config.MyID]
		salt, ok2 := r2j.PairwiseSalts[config.MyID]
		if !ok1 || !ok2 {
			badSenders = append(badSenders, j)
			continue
		}
		if err2 := Open(shareBytes, com, salt); err2 != nil {
			badSenders = append(badSenders, j)
			continue
		}
		var shareVal btcec.ModNScalar
		if overflow := shareVal.SetByteSlice(shareBytes); overflow {
			badSenders = append(badSenders, j)
			continue
		}

		// Step 3: Feldman check: p_j(myID)*G == sum_k C_{j,k} * myID^k.
		if err2 := feldmanVerify(&shareVal, config.MyID, r2j.FeldmanCommitments); err2 != nil {
			badSenders = append(badSenders, j)
			continue
		}

		finalShare.Add(&shareVal)
		shareVal.Zero()
		feldmanByParty[j] = r2j.FeldmanCommitments
	}

	if len(badSenders) > 0 {
		return btcec.ModNScalar{}, nil, &CheatingPartyError{PartyIDs: badSenders, Phase: "DKGFinalize", Detail: "commitment opening, share, or Feldman verification failed"}
	}

	// Compute master public key: pk = sum_j C_{j,0} (EC point addition).
	var pk btcec.JacobianPoint
	for _, j := range config.AllIDs {
		C_j0, err2 := compressedToPoint(feldmanByParty[j][0])
		if err2 != nil {
			return btcec.ModNScalar{}, nil, fmt.Errorf("dkls23: parse C_{%d,0}: %w", j, err2)
		}
		btcec.AddNonConst(&pk, C_j0, &pk)
	}

	pkBytes, err2 := pointToCompressed(&pk)
	if err2 != nil {
		return btcec.ModNScalar{}, nil, fmt.Errorf("dkls23: serialize public key: %w", err2)
	}

	return finalShare, pkBytes, nil
}
