package dkls23

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

// --- πECDSA: 3-round threshold signing protocol (DKLS23 Protocol 3.6) ---
//
// The signing protocol uses FRVOLE for distributed multiplication (realized by
// Protocol 5.2 on top of a fresh OT-extension batch per session, see below),
// FZero for zero-sharing of key shares, and FCom for commitment to nonce points.
//
// Session structure (paper Protocol 3.6):
//   - Setup (once): FRelaxedKeyGen, the λc base OTs per directed pair (the
//     one-time setup of the OT extension, §8.1-8.2), and the FZero seeds.
//   - Round 1 (step 6): commit to R_i; send (sample, sid) to FRVOLE for every
//     counterparty. In the realization this is Bob's fresh OT-extension batch
//     (Functionality 5.1 requires a fresh sid per batch), carried in Round1Msg.
//   - Round 2 (step 7): Alice consumes the batch, runs the VOLE multiply and
//     sends the decommitment and check values.
//   - Round 3 (step 8): verification checks and signature fragments.
//
// Correctness argument:
//   sum_i u_i = sum_i r_i * eff_phi_i + sum_{i,j} (c^u_{i,j} + d^u_{i,j})
//             = phi * R_scalar   (since sum VOLE outputs cancel mod q)
//   sum_i w_i = hash * phi + rx * sk * phi
//   s = sum(w) / sum(u) = (hash + rx*sk) / R_scalar = standard ECDSA s.

// BaseOTSenderSeeds is the one-time base-OT output held by the party that acts
// as base-OT sender for a directed VOLE pair. In the IKNP/KOS role mapping the
// base-OT sender is the OT-extension receiver, i.e. VOLE Bob.
type BaseOTSenderSeeds struct {
	// Seeds0[k] is K^0_k for k ∈ [LambdaC] (32 bytes each).
	Seeds0 [][]byte
	// Seeds1[k] is K^1_k for k ∈ [LambdaC] (32 bytes each).
	Seeds1 [][]byte
}

// BaseOTReceiverSeeds is the one-time base-OT output held by the party that
// acts as base-OT receiver for a directed VOLE pair. The base-OT receiver is
// the OT-extension sender, i.e. VOLE Alice.
type BaseOTReceiverSeeds struct {
	// Seeds[k] is K^{Sigma[k]}_k for k ∈ [LambdaC] (32 bytes each).
	Seeds [][]byte
	// Sigma are the LambdaC base-OT choice bits (the OT-extension sender's Δ).
	Sigma []bool
}

// SignerSetup holds per-signer persistent state initialized once during setup.
// It is reused across multiple signing sessions.
//
// Only the base-OT seeds are persistent (DKLS23 §8.2: "setup for endemic OT
// extension is performed once per pair of parties"). The OT-extension batch
// and the VOLE correlation derived from it are regenerated inside every
// signing session; they must never be stored and reused.
//
// SignerSetup is safe for concurrent use. Every signing round takes the write
// lock for its duration, because each round records the session's progress
// (see SessionIDs) and may blacklist a party; concurrent sessions therefore
// execute their rounds one at a time within one SignerSetup. Refresh takes
// the write lock as well. A SignerSetup must not be copied after first use.
type SignerSetup struct {
	// mu protects all mutable fields below. Unexported so it is excluded from
	// JSON serialization and cannot be misused by callers.
	mu sync.RWMutex
	// MyID is this party's identifier (1-indexed).
	MyID int
	// AllIDs is the sorted list of all DKG participant identifiers.
	AllIDs []int
	// Share is this party's Shamir share p(myID) from DKG.
	Share btcec.ModNScalar
	// PubKey is the master public key (33-byte compressed).
	PubKey []byte
	// Threshold is the signing threshold t.
	Threshold int
	// AliceBaseOT[j] holds the base-OT receiver seeds for the directed VOLE
	// i→j in which this party is Alice (OT-extension sender) and j is Bob.
	AliceBaseOT map[int]*BaseOTReceiverSeeds
	// BobBaseOT[j] holds the base-OT sender seeds for the directed VOLE j→i
	// in which j is Alice and this party is Bob (OT-extension receiver).
	BobBaseOT map[int]*BaseOTSenderSeeds
	// FZeroSeeds[j] is the shared FZero seed between this party and party j.
	FZeroSeeds map[int][16]byte
	// Blacklist records parties detected cheating; they are excluded from future sessions
	// (paper Protocol 3.6 step 8: "does not participate in any future signature
	// signing sessions involving Pj").
	Blacklist map[int]bool
	// Epoch is the proactive refresh epoch counter, starting at 0 and incremented on each RefreshFinalize.
	Epoch int
	// SessionIDs records, for every signing session id used with this setup in
	// the current epoch, the last signing round completed for it (1, 2 or 3).
	// It enforces DKLS23 Protocol 3.6 step 4 ("sigid is not fresh" requests
	// are ignored): SignRound1 rejects an id that was already used, SignRound2
	// requires round 1 and rejects a second round 2, SignRound3 requires round
	// 2 and rejects a second round 3. A session id reuse would reproduce the
	// session's OT-extension batch, so the map is part of the persisted state.
	// RefreshFinalize clears it: the refreshed base-OT and FZero seeds re-key
	// every quantity that depends on the session id, so ids from earlier
	// epochs cannot collide with the new seeds. Between refreshes it grows by
	// one entry per session.
	SessionIDs map[string]int
}

// Signing-session stages recorded in SignerSetup.SessionIDs.
const (
	sessionUnused     = 0
	sessionRound1Done = 1
	sessionRound2Done = 2
	sessionRound3Done = 3
)

// requireSessionStage checks that sigID has completed exactly the round `want`
// on this setup. The caller must hold setup.mu.
func (setup *SignerSetup) requireSessionStage(sigID string, want int, phase string) error {
	got := setup.SessionIDs[sigID]
	switch {
	case got == want:
		return nil
	case got > want:
		return &SessionIDReusedError{SigID: sigID, Phase: phase, Detail: fmt.Sprintf("round %d already completed for this session", got)}
	default:
		return &InvalidInputError{Phase: phase, Detail: fmt.Sprintf("session id %q has not completed round %d on this SignerSetup", sigID, want)}
	}
}

// markSessionStage records that sigID completed `stage`. The caller must hold setup.mu.
func (setup *SignerSetup) markSessionStage(sigID string, stage int) {
	if setup.SessionIDs == nil {
		setup.SessionIDs = make(map[string]int)
	}
	setup.SessionIDs[sigID] = stage
}

// voleSIDForPair constructs the session ID of the FRVOLE instance between
// Alice and Bob for one signing session (paper: Pj‖Pi‖sid‖sigid). The same
// ID is used for the FEOTE batch inside that instance.
func voleSIDForPair(sigID string, aliceID, bobID int) string {
	return fmt.Sprintf("%s:vole:%d->%d", sigID, aliceID, bobID)
}

// Round1State holds Pi's private state after signing round 1.
type Round1State struct {
	// SigID uniquely identifies this signing session.
	SigID string
	// Signers are the party IDs participating in this signing session.
	Signers []int
	// R_i is the nonce scalar sampled by Pi.
	R_i btcec.ModNScalar
	// Phi_i is the inversion mask scalar sampled by Pi.
	Phi_i btcec.ModNScalar
	// R_iPoint is R_i*G (33-byte compressed).
	R_iPoint []byte
	// Com is FCom commitment to R_iPoint.
	Com [32]byte
	// Salt is the FCom salt for Com.
	Salt [SaltLen]byte
	// ZetaI is Pi's FZero zero-sharing value for this session.
	ZetaI btcec.ModNScalar
	// VoleBobForRound2 holds Pi's fresh VOLE Bob state per counterparty j
	// (Pi is Bob, j is Alice), sampled in round 1 for this session only.
	// Used in round 3 to run VOLEBobReceive against j's VOLE multiply message.
	VoleBobForRound2 map[int]*VOLEBobState
}

// Round1Msg is Pi's round 1 message to counterparty Pj.
type Round1Msg struct {
	// Commitment is FCom commitment to R_i*G; the same value is sent to all counterparties.
	Commitment [32]byte
	// OTExt is Pi's fresh OT-extension receiver message for the directed VOLE
	// j→i (Pj is Alice, Pi is Bob). It realizes (sample, Pj‖Pi‖sid‖sigid) to
	// FRVOLE in paper step 6 and is specific to Pj.
	OTExt *OTExtReceiverMsg
}

// checkBlacklist returns a BlacklistedPartyError if any of the given party IDs
// appear in setup.Blacklist.
func checkBlacklist(setup *SignerSetup, partyIDs []int, phase string) error {
	var bad []int
	for _, id := range partyIDs {
		if setup.Blacklist[id] {
			bad = append(bad, id)
		}
	}
	if len(bad) > 0 {
		return &BlacklistedPartyError{PartyIDs: bad, Phase: phase}
	}
	return nil
}

// sampleBeta samples Bob's uniform OT choice bits β ← {0,1}^ξ (paper Protocol 5.2 step 1).
func sampleBeta() ([Xi]bool, error) {
	var beta [Xi]bool
	buf := make([]byte, (Xi+7)/8)
	if _, err := rand.Read(buf); err != nil {
		return beta, err
	}
	for j := 0; j < Xi; j++ {
		beta[j] = (buf[j/8]>>(uint(j)%8))&1 == 1
	}
	for i := range buf {
		buf[i] = 0
	}
	return beta, nil
}

// SignRound1 executes round 1 of the threshold signing protocol (paper §3.6, steps 5-6).
// Pi samples r_i, phi_i, computes R_i = r_i*G and commits to it.
// Pi also computes its FZero zero-sharing value zeta_i and, for every
// counterparty j, samples a fresh FRVOLE instance in which Pi is Bob: a fresh
// OT-extension batch (Functionality 5.1, fresh sid) whose receiver message is
// carried in Round1Msg.OTExt.
func SignRound1(setup *SignerSetup, sigID string, signers []int) (*Round1State, map[int]*Round1Msg, error) {
	setup.mu.Lock()
	defer setup.mu.Unlock()
	if err := validatePartyIDs(signers, "SignRound1"); err != nil {
		return nil, nil, err
	}
	if err := checkBlacklist(setup, signers, "SignRound1"); err != nil {
		return nil, nil, err
	}
	if len(signers) < setup.Threshold {
		return nil, nil, &InvalidInputError{Phase: "SignRound1", Detail: fmt.Sprintf("signer count %d below threshold %d", len(signers), setup.Threshold)}
	}
	myIDFound := false
	for _, id := range signers {
		if id == setup.MyID {
			myIDFound = true
			break
		}
	}
	if !myIDFound {
		return nil, nil, &InvalidInputError{Phase: "SignRound1", Detail: "myID not in signers list"}
	}
	// Paper step 4: ignore the request unless sigid is fresh.
	if sigID == "" {
		return nil, nil, &InvalidInputError{Phase: "SignRound1", Detail: "session id must be non-empty"}
	}
	if err := setup.requireSessionStage(sigID, sessionUnused, "SignRound1"); err != nil {
		return nil, nil, err
	}

	// Sample nonce and inversion mask.
	r_i, err := sampleScalar()
	if err != nil {
		return nil, nil, fmt.Errorf("dkls23 SignRound1: sample r_i: %w", err)
	}
	phi_i, err := sampleScalar()
	if err != nil {
		return nil, nil, fmt.Errorf("dkls23 SignRound1: sample phi_i: %w", err)
	}

	// R_i = r_i * G.
	R_iPoint, err := scalarMulGCompressed(&r_i)
	if err != nil {
		return nil, nil, fmt.Errorf("dkls23 SignRound1: R_i: %w", err)
	}

	// Commit to R_i.
	com, salt, err := Commit(R_iPoint)
	if err != nil {
		return nil, nil, fmt.Errorf("dkls23 SignRound1: commit: %w", err)
	}

	// FZero sample: restrict seeds to this signing session's counterparties.
	signerSeeds := map[int][16]byte{}
	for _, j := range signers {
		if j == setup.MyID {
			continue
		}
		if seed, ok := setup.FZeroSeeds[j]; ok {
			signerSeeds[j] = seed
		}
	}
	zetaI := FZeroSample(signerSeeds, setup.MyID, []byte(sigID))

	// FRVOLE sampling phase (paper Protocol 5.2 step 1) for each counterparty j
	// with Pi as Bob: fresh β, fresh OT-extension batch keyed by this session.
	bobStates := make(map[int]*VOLEBobState)
	outMsgs := make(map[int]*Round1Msg)
	for _, j := range signers {
		if j == setup.MyID {
			continue
		}
		base := setup.BobBaseOT[j]
		if base == nil {
			return nil, nil, &CorruptStateError{Phase: "SignRound1", Detail: fmt.Sprintf("missing base-OT sender seeds for party %d", j)}
		}
		beta, err := sampleBeta()
		if err != nil {
			return nil, nil, fmt.Errorf("dkls23 SignRound1: sample beta for %d: %w", j, err)
		}
		sid := voleSIDForPair(sigID, j, setup.MyID)
		oteMsg, gamma, err := OTExtReceive(base.Seeds0, base.Seeds1, beta, []byte(sid))
		if err != nil {
			return nil, nil, fmt.Errorf("dkls23 SignRound1: OT extension for %d: %w", j, err)
		}
		bobState, err := VOLEBobSample(gamma, beta)
		if err != nil {
			return nil, nil, fmt.Errorf("dkls23 SignRound1: VOLE sample for %d: %w", j, err)
		}
		bobStates[j] = bobState
		outMsgs[j] = &Round1Msg{Commitment: com, OTExt: oteMsg}
	}

	state := &Round1State{
		SigID:            sigID,
		Signers:          signers,
		R_i:              r_i,
		Phi_i:            phi_i,
		R_iPoint:         R_iPoint,
		Com:              com,
		Salt:             salt,
		ZetaI:            zetaI,
		VoleBobForRound2: bobStates,
	}
	// The session's OT-extension batches are about to leave this process:
	// from here on the id is spent.
	setup.markSessionStage(sigID, sessionRound1Done)
	return state, outMsgs, nil
}

// Round2State holds Pi's private state after signing round 2.
type Round2State struct {
	*Round1State
	// SK_i is Pi's rerandomized Shamir share: share*lagrange(signers,myID,0) + zeta_i mod q.
	SK_i btcec.ModNScalar
	// C_u[j] is Pi's VOLE Alice output share for the nonce correlation with Pj.
	C_u map[int]btcec.ModNScalar
	// C_v[j] is Pi's VOLE Alice output share for the key correlation with Pj.
	C_v map[int]btcec.ModNScalar
	// Round1Commits[j] stores j's round 1 commitment for verification in round 3.
	Round1Commits map[int][32]byte
}

// Round2Msg is Pi's message to each counterparty Pj in round 2.
type Round2Msg struct {
	// Decommitment is R_i (33-byte compressed point), revealing the committed nonce.
	Decommitment []byte
	// Salt is the FCom salt for the round 1 commitment.
	Salt [SaltLen]byte
	// VoleMsg is Pi's VOLE multiply message (Pi as Alice, Pj as Bob).
	VoleMsg *VOLEMultiplyMsg
	// GammaU = c^u_{i,j}*G (compressed 33 bytes); used for check 1 in round 3.
	GammaU []byte
	// GammaV = c^v_{i,j}*G (compressed 33 bytes); used for check 2 in round 3.
	GammaV []byte
	// Psi = phi_i - chi_{j->i} mod q (32 bytes big-endian); used for inversion.
	// chi_{j->i} is the VOLE Bob chi where Pi is Bob and Pj is Alice.
	Psi []byte
	// PKi = sk_i*G (compressed 33 bytes); for public key consistency check.
	PKi []byte
}

// SignRound2 executes round 2 of the threshold signing protocol (paper §3.6, step 7).
// For every counterparty j, Pi (as Alice) consumes j's fresh OT-extension batch
// from round 1, verifies its consistency check, derives the session's VOLE
// correlation (Protocol 5.2 step 2), and runs the VOLE multiply (step 3).
// Pi then decommits R_i and sends gamma, psi, and pki for round 3 verification.
//
// If the OT-extension consistency check fails for party j, the shared FRVOLE
// instance with Pj has aborted: j is blacklisted and a CheatingPartyError is
// returned (paper step 8).
func SignRound2(setup *SignerSetup, state *Round1State, allRound1 map[int]*Round1Msg) (*Round2State, map[int]*Round2Msg, error) {
	setup.mu.Lock()
	defer setup.mu.Unlock()
	if err := checkBlacklist(setup, state.Signers, "SignRound2"); err != nil {
		return nil, nil, err
	}
	// Round 2 consumes the counterparties' batches and sends this party's VOLE
	// multiply messages; it may run exactly once per session on this setup.
	if err := setup.requireSessionStage(state.SigID, sessionRound1Done, "SignRound2"); err != nil {
		return nil, nil, err
	}

	// Rerandomize share: sk_i = share * lagrange(signers, myID, 0) + zeta_i mod q.
	lc := lagrangeCoeff(setup.MyID, state.Signers)
	defer lc.Zero()
	var sk_i btcec.ModNScalar
	sk_i.Mul2(&setup.Share, &lc)
	sk_i.Add(&state.ZetaI)

	// sk_i * G for public key consistency check.
	pkiBytes, err := scalarMulGCompressed(&sk_i)
	if err != nil {
		return nil, nil, fmt.Errorf("dkls23 SignRound2: compute PKi: %w", err)
	}

	c_u := make(map[int]btcec.ModNScalar)
	c_v := make(map[int]btcec.ModNScalar)
	outMsgs := make(map[int]*Round2Msg)
	round1Commits := make(map[int][32]byte)
	var badParties []int

	for _, j := range state.Signers {
		if j == setup.MyID {
			continue
		}
		r1j := allRound1[j]
		if r1j == nil || r1j.OTExt == nil {
			return nil, nil, &InvalidInputError{Phase: "SignRound2", Detail: fmt.Sprintf("missing round 1 message from party %d", j)}
		}

		// Record j's round 1 commitment for later verification in round 3.
		round1Commits[j] = r1j.Commitment

		// Pi is Alice in the i→j VOLE direction: consume j's OT-extension batch.
		base := setup.AliceBaseOT[j]
		if base == nil {
			return nil, nil, &CorruptStateError{Phase: "SignRound2", Detail: fmt.Sprintf("missing base-OT receiver seeds for party %d", j)}
		}
		sid := voleSIDForPair(state.SigID, setup.MyID, j)
		alpha0, alpha1, err := OTExtSend(base.Seeds, base.Sigma, []byte(sid), r1j.OTExt)
		if err != nil {
			// FRVOLE instance with Pj aborted (consistency check failed).
			badParties = append(badParties, j)
			setup.Blacklist[j] = true
			continue
		}
		aliceState, err := VOLEAliceSetup(alpha0, alpha1)
		if err != nil {
			return nil, nil, fmt.Errorf("dkls23 SignRound2: VOLE setup with %d: %w", j, err)
		}
		cu, cv, voleMsg, err := VOLEAliceMultiply(aliceState, sid, &state.R_i, &sk_i)
		if err != nil {
			return nil, nil, fmt.Errorf("dkls23 SignRound2: VOLE multiply with %d: %w", j, err)
		}
		c_u[j] = cu
		c_v[j] = cv

		// GammaU = c^u * G, GammaV = c^v * G.
		gammaU, err := scalarMulGCompressed(&cu)
		if err != nil {
			return nil, nil, fmt.Errorf("dkls23 SignRound2: GammaU for %d: %w", j, err)
		}
		gammaV, err := scalarMulGCompressed(&cv)
		if err != nil {
			return nil, nil, fmt.Errorf("dkls23 SignRound2: GammaV for %d: %w", j, err)
		}

		// psi_{i,j} = phi_i - chi_{j->i} mod q.
		// chi_{j->i} is from the VOLE Bob state where Pi is Bob and j is Alice.
		bobStateJI := state.VoleBobForRound2[j]
		if bobStateJI == nil {
			return nil, nil, &CorruptStateError{Phase: "SignRound2", Detail: fmt.Sprintf("missing VOLE Bob state for party %d", j)}
		}
		chiJI := bobStateJI.Chi
		var psi btcec.ModNScalar
		var negChi btcec.ModNScalar
		negChi.NegateVal(&chiJI)
		psi.Add2(&state.Phi_i, &negChi)
		psiArr := psi.Bytes()

		outMsgs[j] = &Round2Msg{
			Decommitment: state.R_iPoint,
			Salt:         state.Salt,
			VoleMsg:      voleMsg,
			GammaU:       gammaU,
			GammaV:       gammaV,
			Psi:          psiArr[:],
			PKi:          pkiBytes,
		}
	}

	if len(badParties) > 0 {
		return nil, nil, &CheatingPartyError{PartyIDs: badParties, Phase: "SignRound2", Detail: "OT extension consistency check failed"}
	}

	state2 := &Round2State{
		Round1State:   state,
		SK_i:          sk_i,
		C_u:           c_u,
		C_v:           c_v,
		Round1Commits: round1Commits,
	}
	setup.markSessionStage(state.SigID, sessionRound2Done)
	return state2, outMsgs, nil
}

// Round3Msg contains Pi's signature fragment, broadcast to all parties for combining.
type Round3Msg struct {
	// W_i is Pi's w contribution: SHA256(msg)*phi_i + rx*v_i mod q.
	W_i []byte // 32-byte big-endian
	// U_i is Pi's u contribution: r_i*eff_phi_i + sum_j (c^u + d^u) mod q.
	U_i []byte // 32-byte big-endian
}

// SignRound3 executes round 3 of the threshold signing protocol (paper §3.6, step 8).
// Pi receives all round 2 messages, verifies checks 1-3, and outputs signature fragments.
//
// Verification checks per counterparty j:
//  1. FCom decommitment: Open(R_j, com_j from round1, salt from round2).
//  2. VOLE Bob receive: d^u_{i,j}, d^v_{i,j} = VOLEBobReceive(state, voleMsg from j).
//  3. Check 1: chi_{j->i} * R_j - Gamma^u_{j,i} == d^u_{i,j} * G
//  4. Check 2: chi_{j->i} * pk_j - Gamma^v_{j,i} == d^v_{i,j} * G
//  5. Check 3: sum_k pk_k == master_pk
//
// If any check fails for party j: blacklist j and return error.
//
// The returned map contains one entry per counterparty plus an entry under
// Pi's own ID holding Pi's own fragment (for use with SignCombine).
func SignRound3(setup *SignerSetup, state2 *Round2State, message []byte, allRound2 map[int]*Round2Msg) (map[int]*Round3Msg, error) {
	setup.mu.Lock()
	defer setup.mu.Unlock()
	if err := checkBlacklist(setup, state2.Signers, "SignRound3"); err != nil {
		return nil, err
	}
	// Round 3 releases this party's signature fragments, which are a function
	// of the counterparties' round 2 values; releasing fragments for two
	// different sets of round 2 inputs would reveal r_i. Exactly once per session.
	if err := setup.requireSessionStage(state2.SigID, sessionRound2Done, "SignRound3"); err != nil {
		return nil, err
	}

	// Collect R_j and pk_j from all parties.
	RPoints := make(map[int]*btcec.JacobianPoint)
	pkjPoints := make(map[int]*btcec.JacobianPoint)
	duMap := make(map[int]btcec.ModNScalar)
	dvMap := make(map[int]btcec.ModNScalar)

	// My own contributions.
	myRPt, err := compressedToPoint(state2.R_iPoint)
	if err != nil {
		return nil, fmt.Errorf("dkls23 SignRound3: parse my R_i: %w", err)
	}
	RPoints[setup.MyID] = myRPt

	myPKiBytes, err := scalarMulGCompressed(&state2.SK_i)
	if err != nil {
		return nil, fmt.Errorf("dkls23 SignRound3: my PKi: %w", err)
	}
	myPKiPt, err := compressedToPoint(myPKiBytes)
	if err != nil {
		return nil, fmt.Errorf("dkls23 SignRound3: parse my PKi: %w", err)
	}
	pkjPoints[setup.MyID] = myPKiPt

	var badParties []int

	for _, j := range state2.Signers {
		if j == setup.MyID {
			continue
		}
		r2j := allRound2[j]
		if r2j == nil {
			badParties = append(badParties, j)
			continue
		}

		// Step 1: Verify FCom decommitment of R_j.
		comJ := state2.Round1Commits[j]
		if err := Open(r2j.Decommitment, comJ, r2j.Salt); err != nil {
			badParties = append(badParties, j)
			setup.Blacklist[j] = true
			continue
		}

		Rj, err := compressedToPoint(r2j.Decommitment)
		if err != nil {
			badParties = append(badParties, j)
			setup.Blacklist[j] = true
			continue
		}
		RPoints[j] = Rj

		pkj, err := compressedToPoint(r2j.PKi)
		if err != nil {
			badParties = append(badParties, j)
			setup.Blacklist[j] = true
			continue
		}
		pkjPoints[j] = pkj

		// Step 2: VOLE Bob receive. Pi is Bob in the j→i VOLE direction.
		bobState := state2.VoleBobForRound2[j]
		if bobState == nil {
			badParties = append(badParties, j)
			setup.Blacklist[j] = true
			continue
		}
		sidJI := voleSIDForPair(state2.SigID, j, setup.MyID)
		du, dv, err := VOLEBobReceive(bobState, sidJI, r2j.VoleMsg)
		if err != nil {
			badParties = append(badParties, j)
			setup.Blacklist[j] = true
			continue
		}
		duMap[j] = du
		dvMap[j] = dv

		// chi_{j->i} = Bob state Chi (Pi is Bob, j is Alice).
		chiJI := bobState.Chi

		// Step 3: Check 1: chi_{j->i} * R_j - Gamma^u_{j,i} == d^u_{i,j} * G
		gammaUJI, err := compressedToPoint(r2j.GammaU)
		if err != nil {
			badParties = append(badParties, j)
			setup.Blacklist[j] = true
			continue
		}
		chiRj := scalarMul(&chiJI, Rj)
		negGammaU := pointNeg(gammaUJI)
		lhs1 := pointAdd(chiRj, negGammaU)
		lhs1.ToAffine()

		var rhs1 btcec.JacobianPoint
		btcec.ScalarBaseMultNonConst(&du, &rhs1)
		rhs1.ToAffine()

		if !lhs1.X.Equals(&rhs1.X) || !lhs1.Y.Equals(&rhs1.Y) {
			badParties = append(badParties, j)
			setup.Blacklist[j] = true
			continue
		}

		// Step 4: Check 2: chi_{j->i} * pk_j - Gamma^v_{j,i} == d^v_{i,j} * G
		gammaVJI, err := compressedToPoint(r2j.GammaV)
		if err != nil {
			badParties = append(badParties, j)
			setup.Blacklist[j] = true
			continue
		}
		chiPKj := scalarMul(&chiJI, pkj)
		negGammaV := pointNeg(gammaVJI)
		lhs2 := pointAdd(chiPKj, negGammaV)
		lhs2.ToAffine()

		var rhs2 btcec.JacobianPoint
		btcec.ScalarBaseMultNonConst(&dv, &rhs2)
		rhs2.ToAffine()

		if !lhs2.X.Equals(&rhs2.X) || !lhs2.Y.Equals(&rhs2.Y) {
			badParties = append(badParties, j)
			setup.Blacklist[j] = true
			continue
		}
	}

	if len(badParties) > 0 {
		return nil, &CheatingPartyError{PartyIDs: badParties, Phase: "SignRound3", Detail: "verification checks failed"}
	}

	// Step 5: Check 3: sum_k pk_k == master_pk.
	var sumPK btcec.JacobianPoint
	for _, j := range state2.Signers {
		btcec.AddNonConst(&sumPK, pkjPoints[j], &sumPK)
	}
	sumPK.ToAffine()

	masterPK, err := compressedToPoint(setup.PubKey)
	if err != nil {
		return nil, fmt.Errorf("dkls23 SignRound3: parse master pubkey: %w", err)
	}
	masterPK.ToAffine()
	if !sumPK.X.Equals(&masterPK.X) || !sumPK.Y.Equals(&masterPK.Y) {
		return nil, &CorruptStateError{Phase: "SignRound3", Detail: "public key consistency check failed: sum(pk_k) != master_pk"}
	}

	// Compute R = sum of all R_j.
	var R btcec.JacobianPoint
	for _, j := range state2.Signers {
		btcec.AddNonConst(&R, RPoints[j], &R)
	}
	R.ToAffine()

	// rx = x-coordinate of R mod q.
	rxBytes := make([]byte, 32)
	R.X.PutBytesUnchecked(rxBytes)
	var rx btcec.ModNScalar
	rx.SetByteSlice(rxBytes)

	// eff_phi_i = phi_i + sum_{j∈signers, j≠i} psi_{j,i}
	var effPhi btcec.ModNScalar
	effPhi.Set(&state2.Phi_i)
	for _, j := range state2.Signers {
		if j == setup.MyID {
			continue
		}
		r2j := allRound2[j]
		var psiJI btcec.ModNScalar
		psiJI.SetByteSlice(r2j.Psi)
		effPhi.Add(&psiJI)
	}

	// u_i = r_i * eff_phi_i + sum_j (c^u_{i,j} + d^u_{i,j}) mod q.
	var u_i btcec.ModNScalar
	u_i.Mul2(&state2.R_i, &effPhi)
	for _, j := range state2.Signers {
		if j == setup.MyID {
			continue
		}
		cu := state2.C_u[j]
		u_i.Add(&cu)
		du := duMap[j]
		u_i.Add(&du)
	}

	// v_i = sk_i * eff_phi_i + sum_j (c^v_{i,j} + d^v_{i,j}) mod q.
	var v_i btcec.ModNScalar
	v_i.Mul2(&state2.SK_i, &effPhi)
	for _, j := range state2.Signers {
		if j == setup.MyID {
			continue
		}
		cv := state2.C_v[j]
		v_i.Add(&cv)
		dv := dvMap[j]
		v_i.Add(&dv)
	}

	// w_i = SHA256(message)*phi_i + rx*v_i mod q.
	msgHash := sha256.Sum256(message)
	var hashScalar btcec.ModNScalar
	hashScalar.SetByteSlice(msgHash[:])

	var w_i btcec.ModNScalar
	w_i.Mul2(&hashScalar, &state2.Phi_i)
	var rxV btcec.ModNScalar
	rxV.Mul2(&rx, &v_i)
	w_i.Add(&rxV)

	defer effPhi.Zero()
	defer u_i.Zero()
	defer v_i.Zero()
	defer w_i.Zero()

	// Build round 3 messages (same fragment broadcast to all).
	wArr := w_i.Bytes()
	uArr := u_i.Bytes()

	outMsgs := make(map[int]*Round3Msg)
	for _, j := range state2.Signers {
		if j == setup.MyID {
			continue
		}
		outMsgs[j] = &Round3Msg{W_i: wArr[:], U_i: uArr[:]}
	}

	// Also return my own fragment through the "self" entry (key = myID).
	outMsgs[setup.MyID] = &Round3Msg{W_i: wArr[:], U_i: uArr[:]}

	setup.markSessionStage(state2.SigID, sessionRound3Done)
	return outMsgs, nil
}

// ComputeRx computes rx = (Σ R_j).x mod q from each signer's decommitted nonce point.
//
// In a distributed setting, each node knows its own R_iPoint (from Round2State)
// and receives the other signers' R_j values as Round2Msg.Decommitment.  This
// function accepts both: pass a map from party ID to the 33-byte compressed
// nonce point for every signer (including yourself).
//
// Example:
//
//	points := map[int][]byte{myID: myR2State.R_iPoint}
//	for j, msg := range inboundRound2 {
//	    points[j] = msg.Decommitment
//	}
//	rx, err := dkls23.ComputeRx(points)
func ComputeRx(noncePoints map[int][]byte) (btcec.ModNScalar, error) {
	if len(noncePoints) == 0 {
		return btcec.ModNScalar{}, &InvalidInputError{Phase: "ComputeRx", Detail: "no nonce points provided"}
	}
	var R btcec.JacobianPoint
	for id, pt := range noncePoints {
		Rj, err := compressedToPoint(pt)
		if err != nil {
			return btcec.ModNScalar{}, &InvalidInputError{
				Phase:  "ComputeRx",
				Detail: fmt.Sprintf("invalid nonce point for party %d: %v", id, err),
			}
		}
		btcec.AddNonConst(&R, Rj, &R)
	}
	R.ToAffine()
	rxBytes := make([]byte, 32)
	R.X.PutBytesUnchecked(rxBytes)
	var rx btcec.ModNScalar
	rx.SetByteSlice(rxBytes)
	return rx, nil
}

// SignCombine collects round 3 fragments and outputs the final ECDSA (r, s) signature
// (paper §3.6, step 10). s = sum(w_j) / sum(u_j) mod q; r = rx.
// Verifies the signature against the master public key before returning.
//
// myW and myU are this party's own fragment. If allRound3 also contains an
// entry under this party's own ID (as returned by SignRound3), that entry is
// ignored so the fragment is not counted twice.
func SignCombine(setup *SignerSetup, rx *btcec.ModNScalar, myW, myU *btcec.ModNScalar, allRound3 map[int]*Round3Msg, message []byte) (r, s []byte, err error) {
	setup.mu.RLock()
	defer setup.mu.RUnlock()

	var sumW, sumU btcec.ModNScalar
	sumW.Set(myW)
	sumU.Set(myU)

	for id, r3j := range allRound3 {
		if id == setup.MyID || r3j == nil {
			continue
		}
		var wj, uj btcec.ModNScalar
		wj.SetByteSlice(r3j.W_i)
		uj.SetByteSlice(r3j.U_i)
		sumW.Add(&wj)
		sumU.Add(&uj)
	}

	// s = sumW * sumU^{-1} mod q.
	if sumU.IsZero() {
		return nil, nil, errors.New("dkls23 SignCombine: sumU is not invertible (nonce sum is zero)")
	}
	sumUInv := scalarInverse(&sumU)
	var sVal btcec.ModNScalar
	sVal.Mul2(&sumW, &sumUInv)

	// Low-S normalization (BIP340 / standard ECDSA): s > q/2 → s = q - s.
	if sVal.IsOverHalfOrder() {
		sVal.Negate()
	}

	rArr := rx.Bytes()
	sArr := sVal.Bytes()
	rBytes := rArr[:]
	sBytes := sArr[:]

	// Verify the signature against the master public key.
	pubKey, err2 := btcec.ParsePubKey(setup.PubKey)
	if err2 != nil {
		return nil, nil, fmt.Errorf("dkls23 SignCombine: parse pubkey: %w", err2)
	}
	msgHash := sha256.Sum256(message)

	var rScalar, sScalar btcec.ModNScalar
	rScalar.SetByteSlice(rBytes)
	sScalar.SetByteSlice(sBytes)
	ecdsaSig := ecdsa.NewSignature(&rScalar, &sScalar)
	if !ecdsaSig.Verify(msgHash[:], pubKey) {
		return nil, nil, errors.New("dkls23 SignCombine: final signature verification failed")
	}

	return rBytes, sBytes, nil
}
