package frost

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"sort"
	"sync"

	"filippo.io/edwards25519"
)

// --- FROST 2-round threshold signing protocol (RFC 9591 Section 5) ---
//
// The signing protocol uses Schnorr's linearity: each signer contributes a
// partial signature z_i that is summed to produce the final (R, z) signature.
// No OT or VOLE is needed. The protocol detects misbehaving signers via
// individual share verification (identifiable abort, RFC 9591 Section 5.4).
//
// Every Element received over the network (nonce commitments, verification
// shares, the group public key) is parsed with deserializeElement and every
// Scalar with SetCanonicalBytes, as RFC 9591 Section 5 requires.

// SignerState holds a signer's persistent state for signing sessions.
// It wraps a KeyShare and tracks blacklisted parties.
//
// SignerState is safe for concurrent use: read-only operations (signing round 1/2)
// acquire a read lock, while mutating operations (blacklisting) acquire a write lock.
type SignerState struct {
	mu sync.RWMutex
	// KeyShare is this signer's key material from DKG.
	KeyShare *KeyShare
	// Blacklist records parties this signer refuses to run signing or
	// refresh sessions with. Nothing in this package adds to it; the
	// application decides when a CheatingPartyError justifies an entry.
	//
	// Be careful with CheatingPartyError values returned by Aggregate.
	// RFC 9591 Section 7 states that "the Coordinator is not trusted with any
	// private information", but FROST's DoS resistance assumes that "the
	// Coordinator does not perform a DoS attack" and that "the Coordinator
	// identifies misbehaving participants such that they can be removed from
	// future invocations of FROST"; Section 5.4 adds that "FROST assumes the
	// network channel is authenticated to identify the signer that
	// misbehaved". A Coordinator that sends one signer a different message or
	// commitment list than it later passes to Aggregate (or, on a channel that
	// is not authenticated, anyone who can alter messages in transit) makes
	// that honest signer's share fail verification: the share is computed over
	// the signer's view of the inputs and checked against the Coordinator's,
	// so Aggregate names the honest signer. Section 7.5 describes the same
	// split-view outcome: "the signing operation will output an invalid
	// signature". Automatically and permanently blacklisting on that basis is
	// therefore only safe when the Coordinator is honest or the round 2 inputs
	// reached every signer by reliable broadcast; otherwise treat the error as
	// a session abort to be investigated.
	Blacklist map[int]bool
	// Epoch is the proactive refresh epoch counter, starting at 0 and
	// incremented on each RefreshFinalize.
	Epoch int
}

// NewSignerState creates a SignerState from a KeyShare.
func NewSignerState(ks *KeyShare) *SignerState {
	return &SignerState{
		KeyShare:  ks,
		Blacklist: make(map[int]bool),
	}
}

// NonceCommitment is a signer's round 1 output: hiding and binding nonce commitments.
// (RFC 9591 Section 5.1)
type NonceCommitment struct {
	// HidingNonceCommitment is D_i = hiding_nonce_i * B (32 bytes).
	HidingNonceCommitment []byte
	// BindingNonceCommitment is E_i = binding_nonce_i * B (32 bytes).
	BindingNonceCommitment []byte
}

// Round1State holds Pi's private nonce state after round 1.
// This state is consumed exactly once in round 2; nonces are zeroized after use.
type Round1State struct {
	// Signers are the party IDs participating in this signing session.
	Signers []int
	// HidingNonce is d_i (secret, zeroized after round 2).
	HidingNonce *edwards25519.Scalar
	// BindingNonce is e_i (secret, zeroized after round 2).
	BindingNonce *edwards25519.Scalar
	// Commitment is this signer's (D_i, E_i) pair.
	Commitment *NonceCommitment
	// consumed tracks whether this state has been used.
	consumed bool
}

// Round2Input bundles the data each signer needs for round 2.
type Round2Input struct {
	// Message is the message to sign.
	Message []byte
	// AllCommitments maps signer ID to their round 1 nonce commitments.
	AllCommitments map[int]*NonceCommitment
}

// SignatureShare is a signer's round 2 output: the partial signature scalar z_i.
// (RFC 9591 Section 5.2)
type SignatureShare struct {
	// SignerID identifies which signer produced this share.
	SignerID int
	// Zi is the signature share scalar (32 bytes little-endian).
	Zi []byte
}

// Signature is a complete Ed25519 signature (R, z) in 64 bytes.
type Signature struct {
	// R is the group commitment (32-byte compressed Edwards point).
	R []byte
	// Z is the aggregate signature scalar (32-byte little-endian).
	Z []byte
}

// Bytes returns the 64-byte encoding R || z.
func (sig *Signature) Bytes() []byte {
	out := make([]byte, 64)
	copy(out[:32], sig.R)
	copy(out[32:], sig.Z)
	return out
}

// checkBlacklist returns a BlacklistedPartyError if any of the given party IDs
// appear in the signer's blacklist.
func checkBlacklist(signer *SignerState, partyIDs []int, phase string) error {
	var bad []int
	for _, id := range partyIDs {
		if signer.Blacklist[id] {
			bad = append(bad, id)
		}
	}
	if len(bad) > 0 {
		return &BlacklistedPartyError{PartyIDs: bad, Phase: phase}
	}
	return nil
}

// SignRound1 generates a (hiding_nonce, binding_nonce) pair and their commitments
// (RFC 9591 Section 5.1, commit). The nonces are generated from a CSPRNG mixed
// with the secret key share for hedging against a bad RNG (Section 4.1,
// nonce_generate).
//
// Nonce reuse across signing sessions is fatal: it enables full key recovery.
func SignRound1(signer *SignerState, signers []int) (*Round1State, *NonceCommitment, error) {
	signer.mu.RLock()
	defer signer.mu.RUnlock()

	if err := validatePartyIDs(signers, "SignRound1"); err != nil {
		return nil, nil, err
	}
	if err := checkBlacklist(signer, signers, "SignRound1"); err != nil {
		return nil, nil, err
	}
	if len(signers) < signer.KeyShare.Threshold {
		return nil, nil, &InvalidInputError{Phase: "SignRound1", Detail: fmt.Sprintf("signer count %d below threshold %d", len(signers), signer.KeyShare.Threshold)}
	}
	myIDFound := false
	for _, id := range signers {
		if id == signer.KeyShare.ID {
			myIDFound = true
			break
		}
	}
	if !myIDFound {
		return nil, nil, &InvalidInputError{Phase: "SignRound1", Detail: "myID not in signers list"}
	}

	hidingNonce, err := nonceGenerate(signer.KeyShare.SecretShare)
	if err != nil {
		return nil, nil, fmt.Errorf("frost SignRound1: generate hiding nonce: %w", err)
	}
	bindingNonce, err := nonceGenerate(signer.KeyShare.SecretShare)
	if err != nil {
		return nil, nil, fmt.Errorf("frost SignRound1: generate binding nonce: %w", err)
	}

	state := &Round1State{
		Signers:      signers,
		HidingNonce:  hidingNonce,
		BindingNonce: bindingNonce,
		Commitment:   commitNonces(hidingNonce, bindingNonce),
	}

	return state, state.Commitment, nil
}

// commitNonces computes (D_i, E_i) = (hiding_nonce * B, binding_nonce * B)
// (RFC 9591 Section 5.1, commit).
func commitNonces(hidingNonce, bindingNonce *edwards25519.Scalar) *NonceCommitment {
	return &NonceCommitment{
		HidingNonceCommitment:  edwards25519.NewGeneratorPoint().ScalarBaseMult(hidingNonce).Bytes(),
		BindingNonceCommitment: edwards25519.NewGeneratorPoint().ScalarBaseMult(bindingNonce).Bytes(),
	}
}

// nonceGenerate implements RFC 9591 Section 4.1 nonce_generate:
//
//	random_bytes = random_bytes(32)
//	secret_enc = G.SerializeScalar(secret)
//	return H3(random_bytes || secret_enc)
//
// This hedges against a bad RNG by mixing in the secret key share. secret is
// the 32-byte serialized share.
func nonceGenerate(secret []byte) (*edwards25519.Scalar, error) {
	var randomBytes [32]byte
	if _, err := rand.Read(randomBytes[:]); err != nil {
		return nil, err
	}
	nonce := deriveNonce(randomBytes, secret)
	for i := range randomBytes {
		randomBytes[i] = 0
	}
	return nonce, nil
}

// deriveNonce is the deterministic part of nonce_generate (RFC 9591
// Section 4.1): H3(random_bytes || secret_enc). It is split out so the
// Appendix E test vectors, which fix random_bytes, can exercise it.
func deriveNonce(randomBytes [32]byte, secret []byte) *edwards25519.Scalar {
	input := make([]byte, 32+len(secret))
	copy(input[:32], randomBytes[:])
	copy(input[32:], secret)
	nonce := H3(input)
	// Zeroize: input contains randomBytes || secret (plaintext key material).
	for i := range input {
		input[i] = 0
	}
	return nonce
}

// SignRound2 computes signer i's signature share (RFC 9591 Section 5.2, sign).
//
// Input validation, as Section 5.2 requires, happens before any secret is
// touched: every commitment in the list is parsed with DeserializeElement,
// the list must contain exactly this signer's own round 1 commitment under
// its own identifier, and the group public key must be a valid Element. Then:
//  1. Encode the commitment list and compute binding factors via H1.
//  2. Compute the group commitment R = sum(D_i + rho_i * E_i).
//  3. Compute the challenge c = H2(R || PK || msg).
//  4. Compute z_i = d_i + rho_i * e_i + lambda_i * s_i * c.
//  5. Zeroize d_i and e_i; the Round1State cannot be used again.
func SignRound2(signer *SignerState, state *Round1State, input *Round2Input) (*SignatureShare, error) {
	signer.mu.RLock()
	defer signer.mu.RUnlock()

	if state.consumed {
		return nil, &CorruptStateError{Phase: "SignRound2", Detail: "round 1 state already consumed (nonce reuse prevented)"}
	}
	if _, err := deserializeElement(signer.KeyShare.PublicKey); err != nil {
		return nil, &CorruptStateError{Phase: "SignRound2", Detail: fmt.Sprintf("invalid group public key: %v", err)}
	}

	// Sort signers for deterministic encoding.
	signersSorted := make([]int, len(state.Signers))
	copy(signersSorted, state.Signers)
	sort.Ints(signersSorted)

	// Validate the commitment list (RFC 9591 Section 5.2): every Element
	// must deserialize, and our own identifier must map to our own
	// round 1 commitment.
	parsed, err := parseCommitmentList(input.AllCommitments, signersSorted)
	if err != nil {
		return nil, &InvalidInputError{Phase: "SignRound2", Detail: err.Error()}
	}
	myID := signer.KeyShare.ID
	own := input.AllCommitments[myID]
	if own == nil || state.Commitment == nil ||
		subtle.ConstantTimeCompare(own.HidingNonceCommitment, state.Commitment.HidingNonceCommitment) != 1 ||
		subtle.ConstantTimeCompare(own.BindingNonceCommitment, state.Commitment.BindingNonceCommitment) != 1 {
		return nil, &InvalidInputError{Phase: "SignRound2", Detail: fmt.Sprintf("commitment list entry for signer %d is not this signer's round 1 commitment", myID)}
	}

	// Step 1: Compute binding factors.
	bindingFactors := computeBindingFactors(signer.KeyShare.PublicKey, input.AllCommitments, input.Message, signersSorted)

	// Step 2: Compute group commitment R.
	groupCommitment := computeGroupCommitment(parsed, bindingFactors, signersSorted)

	// Step 3: Compute challenge c = H2(R || PK || msg).
	challenge := computeChallenge(groupCommitment, signer.KeyShare.PublicKey, input.Message)

	// Step 4: Compute z_i = d_i + rho_i * e_i + lambda_i * s_i * c.
	rhoI := bindingFactors[myID]
	lambdaI := lagrangeCoeff(myID, signersSorted)

	sk, err := edwards25519.NewScalar().SetCanonicalBytes(signer.KeyShare.SecretShare)
	if err != nil {
		return nil, &CorruptStateError{Phase: "SignRound2", Detail: "invalid secret share"}
	}

	// z_i = d_i + rho_i * e_i + lambda_i * s_i * c
	rhoE := edwards25519.NewScalar().Multiply(rhoI, state.BindingNonce)
	lambdaSC := edwards25519.NewScalar().Multiply(lambdaI, sk)
	lambdaSC.Multiply(lambdaSC, challenge)

	zi := edwards25519.NewScalar()
	zi.Add(zi, state.HidingNonce)
	zi.Add(zi, rhoE)
	zi.Add(zi, lambdaSC)

	// Step 5: Zeroize nonces and intermediate secrets.
	zeroScalar := edwards25519.NewScalar()
	state.HidingNonce.Set(zeroScalar)
	state.BindingNonce.Set(zeroScalar)
	rhoE.Set(zeroScalar)
	lambdaSC.Set(zeroScalar)
	sk.Set(zeroScalar)
	state.consumed = true

	return &SignatureShare{
		SignerID: myID,
		Zi:       zi.Bytes(),
	}, nil
}

// Aggregate collects signature shares and produces the final 64-byte Ed25519
// signature (RFC 9591 Section 5.3, aggregate):
//  1. Validate inputs: the group public key and every nonce commitment are
//     parsed with DeserializeElement, every share with DeserializeScalar.
//  2. Recompute the binding factors, group commitment R, and challenge c.
//  3. If verificationShares is non-nil, verify each share with
//     verify_signature_share (Section 5.3); a failure aborts with a
//     CheatingPartyError listing the signers whose shares did not verify.
//  4. z = sum(z_i); return (R, z).
//  5. Verify the final signature against the group public key, as
//     Section 5.3 says the Coordinator SHOULD before releasing it.
//
// groupPublicKey and verificationShares (signer ID -> PK_i = s_i * B) MUST
// come from the caller's previously stored group info (Section 5.3), not from
// the signing session's messages.
//
// On attributing blame: a CheatingPartyError from step 3 means the named
// signer's z_i is inconsistent with the commitment list, message, and public
// keys as seen by this aggregator. RFC 9591 Section 7 states that "the
// Coordinator is not trusted with any private information" but that FROST's
// DoS resistance assumes "the Coordinator does not perform a DoS attack" and
// that the channel is "authenticated and reliable". An equivocating
// Coordinator (or relay) that gives an honest signer a different message or
// commitment list than the one passed here causes that signer's share to fail
// verification, so the error names an honest party. Only treat it as proof of
// cheating, and in particular only blacklist automatically, when the
// Coordinator is honest or round 2 inputs were delivered by reliable
// broadcast; see SignerState.Blacklist.
func Aggregate(
	allCommitments map[int]*NonceCommitment,
	allShares map[int]*SignatureShare,
	message []byte,
	groupPublicKey []byte,
	verificationShares map[int][]byte,
	signers []int,
) (*Signature, error) {
	if err := validatePartyIDs(signers, "Aggregate"); err != nil {
		return nil, err
	}
	if _, err := deserializeElement(groupPublicKey); err != nil {
		return nil, &InvalidInputError{Phase: "Aggregate", Detail: fmt.Sprintf("invalid group public key: %v", err)}
	}

	// Sort signers for deterministic encoding.
	signersSorted := make([]int, len(signers))
	copy(signersSorted, signers)
	sort.Ints(signersSorted)

	// Step 1: Validate the commitment list and the shares.
	parsed, err := parseCommitmentList(allCommitments, signersSorted)
	if err != nil {
		return nil, &InvalidInputError{Phase: "Aggregate", Detail: err.Error()}
	}
	for _, id := range signersSorted {
		if allShares[id] == nil {
			if verificationShares != nil {
				// Reported below as a signer that failed to contribute.
				continue
			}
			return nil, &InvalidInputError{Phase: "Aggregate", Detail: fmt.Sprintf("missing signature share for signer %d", id)}
		}
	}

	// Step 2: Recompute binding factors, group commitment, and challenge.
	bindingFactors := computeBindingFactors(groupPublicKey, allCommitments, message, signersSorted)
	groupCommitment := computeGroupCommitment(parsed, bindingFactors, signersSorted)
	challenge := computeChallenge(groupCommitment, groupPublicKey, message)

	// Step 3: Verify individual shares if verification shares are provided.
	if verificationShares != nil {
		var badSigners []int
		for _, id := range signersSorted {
			PKi, err := deserializeElement(verificationShares[id])
			if err != nil {
				return nil, &InvalidInputError{Phase: "Aggregate", Detail: fmt.Sprintf("invalid verification share for signer %d: %v", id, err)}
			}
			share := allShares[id]
			if share == nil {
				badSigners = append(badSigners, id)
				continue
			}
			if err := verifySignatureShare(share, parsed[id], bindingFactors[id], challenge, id, signersSorted, PKi); err != nil {
				badSigners = append(badSigners, id)
			}
		}
		if len(badSigners) > 0 {
			return nil, &CheatingPartyError{PartyIDs: badSigners, Phase: "Aggregate", Detail: "signature share verification failed"}
		}
	}

	// Step 4: z = sum(z_i).
	z := edwards25519.NewScalar()
	for _, id := range signersSorted {
		zi, err := edwards25519.NewScalar().SetCanonicalBytes(allShares[id].Zi)
		if err != nil {
			return nil, &InvalidInputError{Phase: "Aggregate", Detail: fmt.Sprintf("invalid signature share from signer %d", id)}
		}
		z.Add(z, zi)
	}

	sig := &Signature{
		R: groupCommitment.Bytes(),
		Z: z.Bytes(),
	}

	// Step 5: Verify the final signature.
	if !Verify(groupPublicKey, message, sig) {
		return nil, &CorruptStateError{Phase: "Aggregate", Detail: "final signature verification failed"}
	}

	return sig, nil
}

// parsedCommitment is a signer's nonce commitment pair after DeserializeElement.
type parsedCommitment struct {
	D *edwards25519.Point // hiding nonce commitment
	E *edwards25519.Point // binding nonce commitment
}

// parseCommitmentList validates a received commitment list (RFC 9591
// Section 5.2 and 5.3): every signer in signersSorted must have an entry and
// both of its Elements must pass deserializeElement.
func parseCommitmentList(allCommitments map[int]*NonceCommitment, signersSorted []int) (map[int]parsedCommitment, error) {
	parsed := make(map[int]parsedCommitment, len(signersSorted))
	for _, id := range signersSorted {
		comm := allCommitments[id]
		if comm == nil {
			return nil, fmt.Errorf("frost: missing commitment for signer %d", id)
		}
		D, err := deserializeElement(comm.HidingNonceCommitment)
		if err != nil {
			return nil, fmt.Errorf("frost: invalid hiding nonce commitment for signer %d: %w", id, err)
		}
		E, err := deserializeElement(comm.BindingNonceCommitment)
		if err != nil {
			return nil, fmt.Errorf("frost: invalid binding nonce commitment for signer %d: %w", id, err)
		}
		parsed[id] = parsedCommitment{D: D, E: E}
	}
	return parsed, nil
}

// bindingFactorInputs computes rho_input for each signer (RFC 9591 Section 4.4):
//
//	rho_input_prefix = SerializeElement(PK) || H4(msg) || H5(encode_group_commitment_list)
//	rho_input_i      = rho_input_prefix || SerializeScalar(i)
//
// The commitment list must already be validated; its encodings are hashed as
// received (which equal the canonical encodings, since deserializeElement
// rejects non-canonical ones).
func bindingFactorInputs(
	groupPublicKey []byte,
	allCommitments map[int]*NonceCommitment,
	msg []byte,
	signersSorted []int,
) map[int][]byte {
	encodedCommitments := encodeCommitmentList(allCommitments, signersSorted)
	msgHash := H4(msg)
	comHash := H5(encodedCommitments)

	prefix := make([]byte, 0, len(groupPublicKey)+len(msgHash)+len(comHash))
	prefix = append(prefix, groupPublicKey...)
	prefix = append(prefix, msgHash...)
	prefix = append(prefix, comHash...)

	inputs := make(map[int][]byte, len(signersSorted))
	for _, id := range signersSorted {
		idBytes := serializeScalarID(id)
		input := make([]byte, 0, len(prefix)+len(idBytes))
		input = append(input, prefix...)
		input = append(input, idBytes...)
		inputs[id] = input
	}
	return inputs
}

// computeBindingFactors computes the binding factor rho_i = H1(rho_input_i)
// for each signer (RFC 9591 Section 4.4, compute_binding_factors).
func computeBindingFactors(
	groupPublicKey []byte,
	allCommitments map[int]*NonceCommitment,
	msg []byte,
	signersSorted []int,
) map[int]*edwards25519.Scalar {
	inputs := bindingFactorInputs(groupPublicKey, allCommitments, msg, signersSorted)
	factors := make(map[int]*edwards25519.Scalar, len(signersSorted))
	for _, id := range signersSorted {
		factors[id] = H1(inputs[id])
	}
	return factors
}

// computeGroupCommitment computes R = sum(D_i + rho_i * E_i) over all signers
// (RFC 9591 Section 4.5, compute_group_commitment).
func computeGroupCommitment(
	parsed map[int]parsedCommitment,
	bindingFactors map[int]*edwards25519.Scalar,
	signersSorted []int,
) *edwards25519.Point {
	R := edwards25519.NewIdentityPoint()
	for _, id := range signersSorted {
		comm := parsed[id]
		rhoEi := edwards25519.NewIdentityPoint().ScalarMult(bindingFactors[id], comm.E)
		contrib := edwards25519.NewIdentityPoint().Add(comm.D, rhoEi)
		R.Add(R, contrib)
	}
	return R
}

// computeChallenge computes c = H2(R || PK || msg) (RFC 9591 Section 4.6,
// compute_challenge; with H2 the RFC 8032 challenge hash).
func computeChallenge(groupCommitment *edwards25519.Point, groupPublicKey []byte, msg []byte) *edwards25519.Scalar {
	rBytes := groupCommitment.Bytes()
	input := make([]byte, 0, ElementLen+ElementLen+len(msg))
	input = append(input, rBytes...)
	input = append(input, groupPublicKey...)
	input = append(input, msg...)
	return H2(input)
}

// encodeCommitmentList encodes the list of (id, D_i, E_i) in canonical order.
// Each entry: identifier (ScalarLen bytes LE) || D_i (ElementLen bytes) || E_i (ElementLen bytes).
// (RFC 9591 Section 4.3, encode_group_commitment_list)
func encodeCommitmentList(allCommitments map[int]*NonceCommitment, signersSorted []int) []byte {
	entrySize := ScalarLen + 2*ElementLen
	buf := make([]byte, 0, len(signersSorted)*entrySize)
	for _, id := range signersSorted {
		comm := allCommitments[id]
		idBytes := serializeScalarID(id)
		buf = append(buf, idBytes...)
		buf = append(buf, comm.HidingNonceCommitment...)
		buf = append(buf, comm.BindingNonceCommitment...)
	}
	return buf
}

// serializeScalarID serializes a party identifier as a ScalarLen-byte little-endian value.
// (RFC 9591 uses Scalar serialization for identifiers.)
func serializeScalarID(id int) []byte {
	var buf [ScalarLen]byte
	binary.LittleEndian.PutUint64(buf[:8], uint64(id))
	return buf[:]
}

// verifySignatureShare verifies a single share (RFC 9591 Section 5.3,
// verify_signature_share):
//
//	z_i * B == D_i + rho_i * E_i + c * lambda_i * PK_i
//
// commitment and PKi must already have been validated with deserializeElement.
func verifySignatureShare(
	share *SignatureShare,
	commitment parsedCommitment,
	bindingFactor *edwards25519.Scalar,
	challenge *edwards25519.Scalar,
	signerID int,
	allSigners []int,
	PKi *edwards25519.Point,
) error {
	zi, err := edwards25519.NewScalar().SetCanonicalBytes(share.Zi)
	if err != nil {
		return fmt.Errorf("frost: invalid signature share scalar")
	}

	// LHS = z_i * B
	lhs := edwards25519.NewGeneratorPoint().ScalarBaseMult(zi)

	// RHS = D_i + rho_i * E_i + c * lambda_i * PK_i
	lambdaI := lagrangeCoeff(signerID, allSigners)
	cLambda := edwards25519.NewScalar().Multiply(challenge, lambdaI)

	rhoEi := edwards25519.NewIdentityPoint().ScalarMult(bindingFactor, commitment.E)
	cLambdaPKi := edwards25519.NewIdentityPoint().ScalarMult(cLambda, PKi)

	rhs := edwards25519.NewIdentityPoint().Add(commitment.D, rhoEi)
	rhs.Add(rhs, cLambdaPKi)

	if lhs.Equal(rhs) != 1 {
		return fmt.Errorf("frost: signature share verification failed for signer %d", signerID)
	}
	return nil
}
