package frost

import (
	"crypto/ed25519"
	"testing"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dkgSession holds every party's state of a DKG run.
type dkgSession struct {
	allIDs  []int
	configs map[int]DKGPartyConfig
	coeffs  map[int][]*edwards25519.Scalar
	r1      map[int]*DKGRound1Output
	r2      map[int]*DKGRound2Output
}

// runDKGRound1 runs DKGRound1 for every party under the shared test context.
func runDKGRound1(t *testing.T, allIDs []int, threshold int) *dkgSession {
	t.Helper()
	s := &dkgSession{
		allIDs:  allIDs,
		configs: make(map[int]DKGPartyConfig),
		coeffs:  make(map[int][]*edwards25519.Scalar),
		r1:      make(map[int]*DKGRound1Output),
		r2:      make(map[int]*DKGRound2Output),
	}
	for _, id := range allIDs {
		cfg := DKGPartyConfig{MyID: id, AllIDs: allIDs, Threshold: threshold, Context: dkgTestContext}
		s.configs[id] = cfg
		out, c, err := DKGRound1(cfg)
		require.NoError(t, err)
		s.r1[id] = out
		s.coeffs[id] = c
	}
	return s
}

// runDKGRound2 runs DKGRound2 for every party; every proof must verify.
func runDKGRound2(t *testing.T, s *dkgSession) {
	t.Helper()
	for _, id := range s.allIDs {
		out, err := DKGRound2(s.configs[id], s.coeffs[id], s.r1)
		require.NoError(t, err)
		s.r2[id] = out
	}
}

// requireCheating asserts err is a CheatingPartyError naming exactly want.
func requireCheating(t *testing.T, err error, want ...int) {
	t.Helper()
	require.Error(t, err)
	var cheatErr *CheatingPartyError
	require.ErrorAs(t, err, &cheatErr)
	assert.Equal(t, want, cheatErr.PartyIDs)
}

// requireRound2AndFinalizeReject asserts that both DKGRound2 and DKGFinalize,
// run by honest party honest, reject the session naming exactly cheater.
func requireRound2AndFinalizeReject(t *testing.T, s *dkgSession, honest, cheater int) {
	t.Helper()
	_, err := DKGRound2(s.configs[honest], s.coeffs[honest], s.r1)
	requireCheating(t, err, cheater)
	_, err = DKGFinalize(s.configs[honest], s.coeffs[honest], s.r1, s.r2)
	requireCheating(t, err, cheater)
}

func TestDKG3of3(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)

	// All parties agree on the same public key.
	pk := keyShares[1].PublicKey
	for _, id := range []int{2, 3} {
		assert.Equal(t, pk, keyShares[id].PublicKey, "public key mismatch for party %d", id)
	}

	// All parties agree on the same group commitments.
	for _, id := range []int{2, 3} {
		assert.Equal(t, keyShares[1].GroupCommitments, keyShares[id].GroupCommitments, "group commitments mismatch for party %d", id)
	}

	// Verification shares are valid: s_i * B matches.
	for _, id := range []int{1, 2, 3} {
		sk, err := edwards25519.NewScalar().SetCanonicalBytes(keyShares[id].SecretShare)
		require.NoError(t, err)
		expected := edwards25519.NewGeneratorPoint().ScalarBaseMult(sk).Bytes()
		assert.Equal(t, expected, keyShares[id].VerificationShare, "verification share mismatch for party %d", id)
	}
}

func TestDKG2of3(t *testing.T) {
	t.Parallel()
	keyShares, err := buildDKG([]int{1, 2, 3}, 2)
	require.NoError(t, err)

	// All parties agree on public key.
	pk := keyShares[1].PublicKey
	for _, id := range []int{2, 3} {
		assert.Equal(t, pk, keyShares[id].PublicKey)
	}
}

// TestDKGHonestConfigurations runs the full DKG (with proofs of knowledge) in
// several configurations, including non-contiguous identifiers, and checks the
// resulting shares sign correctly.
func TestDKGHonestConfigurations(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		allIDs    []int
		threshold int
		signers   []int
	}{
		{"2-of-3", []int{1, 2, 3}, 2, []int{1, 3}},
		{"3-of-3", []int{1, 2, 3}, 3, []int{1, 2, 3}},
		{"2-of-2", []int{1, 2}, 2, []int{1, 2}},
		{"2-of-3 sparse IDs", []int{2, 5, 9}, 2, []int{5, 9}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			keyShares, err := buildDKG(tc.allIDs, tc.threshold)
			require.NoError(t, err)
			pk := keyShares[tc.allIDs[0]].PublicKey
			for _, id := range tc.allIDs {
				assert.Equal(t, pk, keyShares[id].PublicKey)
				assert.Equal(t, tc.threshold, keyShares[id].Threshold)
			}
			msg := []byte("honest DKG " + tc.name)
			sig := fullSign(t, keyShares, tc.signers, msg)
			assert.True(t, Verify(pk, msg, sig))
			assert.True(t, ed25519.Verify(ed25519.PublicKey(pk), msg, sig.Bytes()))
		})
	}
}

func TestDKGSharesAreShamir(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)

	// Reconstruct secret via Lagrange interpolation at x=0.
	allIDs := []int{1, 2, 3}
	reconstructed := edwards25519.NewScalar()
	for _, id := range allIDs {
		sk, err := edwards25519.NewScalar().SetCanonicalBytes(keyShares[id].SecretShare)
		require.NoError(t, err)
		lc := lagrangeCoeff(id, allIDs)
		term := edwards25519.NewScalar().Multiply(sk, lc)
		reconstructed.Add(reconstructed, term)
	}

	// Reconstructed secret * B should equal group public key.
	expected := edwards25519.NewGeneratorPoint().ScalarBaseMult(reconstructed).Bytes()
	assert.Equal(t, keyShares[1].PublicKey, expected)
}

func TestDKG2of3SubsetReconstruction(t *testing.T) {
	t.Parallel()
	keyShares, err := buildDKG([]int{1, 2, 3}, 2)
	require.NoError(t, err)

	// Any 2-of-3 subset should reconstruct the same secret.
	subsets := [][]int{{1, 2}, {1, 3}, {2, 3}}
	var secrets []*edwards25519.Scalar
	for _, subset := range subsets {
		reconstructed := edwards25519.NewScalar()
		for _, id := range subset {
			sk, err := edwards25519.NewScalar().SetCanonicalBytes(keyShares[id].SecretShare)
			require.NoError(t, err)
			lc := lagrangeCoeff(id, subset)
			term := edwards25519.NewScalar().Multiply(sk, lc)
			reconstructed.Add(reconstructed, term)
		}
		secrets = append(secrets, reconstructed)
	}

	// All subsets reconstruct the same secret.
	for i := 1; i < len(secrets); i++ {
		assert.Equal(t, secrets[0].Bytes(), secrets[i].Bytes(), "subset %d produced different secret", i)
	}

	// And the reconstructed secret matches the public key.
	expected := edwards25519.NewGeneratorPoint().ScalarBaseMult(secrets[0]).Bytes()
	assert.Equal(t, keyShares[1].PublicKey, expected)
}

func TestDKGInvalidInputs(t *testing.T) {
	t.Parallel()

	_, _, err := DKGRound1(DKGPartyConfig{MyID: 1, AllIDs: []int{1, 2}, Threshold: 0})
	assert.Error(t, err, "zero threshold")

	_, _, err = DKGRound1(DKGPartyConfig{MyID: 1, AllIDs: []int{1, 2}, Threshold: 3})
	assert.Error(t, err, "threshold exceeds party count")

	_, _, err = DKGRound1(DKGPartyConfig{MyID: 5, AllIDs: []int{1, 2}, Threshold: 2})
	assert.Error(t, err, "myID not in AllIDs")

	_, _, err = DKGRound1(DKGPartyConfig{MyID: 1, AllIDs: []int{1, 1}, Threshold: 2})
	assert.Error(t, err, "duplicate IDs")

	_, _, err = DKGRound1(DKGPartyConfig{MyID: 0, AllIDs: []int{0, 1}, Threshold: 2})
	assert.Error(t, err, "zero party ID")
}

// TestDKGRejectsEmptyContext: the context string Φ is what makes a proof of
// knowledge non-replayable (FROST paper Figure 1), so an empty Φ is refused by
// every DKG round before any proof is produced or verified.
func TestDKGRejectsEmptyContext(t *testing.T) {
	t.Parallel()
	var inputErr *InvalidInputError

	for _, ctx := range [][]byte{nil, {}} {
		_, _, err := DKGRound1(DKGPartyConfig{MyID: 1, AllIDs: []int{1, 2, 3}, Threshold: 2, Context: ctx})
		require.ErrorAs(t, err, &inputErr)
		assert.Contains(t, inputErr.Detail, "context")
	}

	// A party whose config lost its context after round 1 cannot continue:
	// round 2 and finalize refuse rather than verifying proofs under Φ = "".
	s := runDKGRound1(t, []int{1, 2, 3}, 2)
	runDKGRound2(t, s)
	noCtx := s.configs[1]
	noCtx.Context = nil
	_, err := DKGRound2(noCtx, s.coeffs[1], s.r1)
	require.ErrorAs(t, err, &inputErr)
	_, err = DKGFinalize(noCtx, s.coeffs[1], s.r1, s.r2)
	require.ErrorAs(t, err, &inputErr)

	// With the context restored the same inputs finalize.
	_, err = DKGFinalize(s.configs[1], s.coeffs[1], s.r1, s.r2)
	require.NoError(t, err)
}

func TestDKGRound2AndFinalizeInvalidInputs(t *testing.T) {
	t.Parallel()
	s := runDKGRound1(t, []int{1, 2, 3}, 2)

	var inputErr *InvalidInputError

	// Wrong number of coefficients for the configured threshold.
	_, err := DKGRound2(s.configs[1], s.coeffs[1][:1], s.r1)
	require.ErrorAs(t, err, &inputErr)
	_, err = DKGFinalize(s.configs[1], nil, s.r1, s.r2)
	require.ErrorAs(t, err, &inputErr)

	// Missing round 1 message from party 3: nothing is released.
	partial := map[int]*DKGRound1Output{1: s.r1[1], 2: s.r1[2]}
	_, err = DKGRound2(s.configs[1], s.coeffs[1], partial)
	requireCheating(t, err, 3)

	// Wrong commitment count (an extra commitment) from party 2.
	runDKGRound2(t, s)
	s.r1[2].FeldmanCommitments = append(s.r1[2].FeldmanCommitments, s.r1[2].FeldmanCommitments[1])
	requireRound2AndFinalizeReject(t, s, 1, 2)
}

func TestDKGFinalizeMissingRound1(t *testing.T) {
	t.Parallel()
	s := runDKGRound1(t, []int{1, 2, 3}, 3)
	runDKGRound2(t, s)

	// Remove party 2's round 1 output — party 1 should detect it.
	r1Missing := map[int]*DKGRound1Output{1: s.r1[1], 3: s.r1[3]}
	_, err := DKGFinalize(s.configs[1], s.coeffs[1], r1Missing, s.r2)
	requireCheating(t, err, 2)
}

// TestDKGFinalizeWithoutOwnRound1 checks that a party's own contribution is
// taken from its coefficients, so its own round 1 message need not be in the
// map (and a missing entry does not panic).
func TestDKGFinalizeWithoutOwnRound1(t *testing.T) {
	t.Parallel()
	s := runDKGRound1(t, []int{1, 2, 3}, 2)
	runDKGRound2(t, s)

	full, err := DKGFinalize(s.configs[1], s.coeffs[1], s.r1, s.r2)
	require.NoError(t, err)
	others := map[int]*DKGRound1Output{2: s.r1[2], 3: s.r1[3]}
	withoutOwn, err := DKGFinalize(s.configs[1], s.coeffs[1], others, s.r2)
	require.NoError(t, err)
	assert.Equal(t, full.PublicKey, withoutOwn.PublicKey)
	assert.Equal(t, full.SecretShare, withoutOwn.SecretShare)
	assert.Equal(t, full.GroupCommitments, withoutOwn.GroupCommitments)
}

func TestDKGCheatingDetection(t *testing.T) {
	t.Parallel()
	s := runDKGRound1(t, []int{1, 2, 3}, 3)
	runDKGRound2(t, s)

	// Corrupt party 2's share sent to party 1.
	s.r2[2].SecretShares[1] = make([]byte, 32) // zero share won't match commitments

	_, err := DKGFinalize(s.configs[1], s.coeffs[1], s.r1, s.r2)
	requireCheating(t, err, 2)
}

func TestDKG2of2Minimal(t *testing.T) {
	t.Parallel()
	keyShares, err := buildDKG([]int{1, 2}, 2)
	require.NoError(t, err)
	assert.Equal(t, keyShares[1].PublicKey, keyShares[2].PublicKey)

	// Sign with the minimal 2-of-2 setup.
	msg := []byte("2-of-2 minimal threshold")
	sig := fullSign(t, keyShares, []int{1, 2}, msg)
	assert.True(t, Verify(keyShares[1].PublicKey, msg, sig))
}

func TestDKGWrongCommitmentCount(t *testing.T) {
	t.Parallel()
	s := runDKGRound1(t, []int{1, 2, 3}, 3)
	runDKGRound2(t, s)

	// Party 2 sends wrong number of Feldman commitments (2 instead of 3).
	s.r1[2].FeldmanCommitments = s.r1[2].FeldmanCommitments[:2]
	requireRound2AndFinalizeReject(t, s, 1, 2)
}

func TestDKGBadShareLength(t *testing.T) {
	t.Parallel()
	s := runDKGRound1(t, []int{1, 2, 3}, 3)
	runDKGRound2(t, s)

	// Party 2 sends a truncated share to party 1.
	s.r2[2].SecretShares[1] = []byte{0x01, 0x02} // too short

	_, err := DKGFinalize(s.configs[1], s.coeffs[1], s.r1, s.r2)
	requireCheating(t, err, 2)
}

func TestDKGNonCanonicalShare(t *testing.T) {
	t.Parallel()
	s := runDKGRound1(t, []int{1, 2, 3}, 3)
	runDKGRound2(t, s)

	// Party 2 sends a non-canonical scalar (all 0xff, >= group order).
	nonCanonical := make([]byte, 32)
	for i := range nonCanonical {
		nonCanonical[i] = 0xff
	}
	s.r2[2].SecretShares[1] = nonCanonical

	_, err := DKGFinalize(s.configs[1], s.coeffs[1], s.r1, s.r2)
	requireCheating(t, err, 2)
}

// --- Proof of knowledge of a_{i,0} (FROST paper Figure 1) ---

// TestDKGProofOfKnowledgeFormula checks dkgProveKnowledge against the
// equations of Figure 1 step 2 computed by hand, that the proof verifies with
// Figure 1 step 5, and that the proof nonce k is zeroized.
func TestDKGProofOfKnowledgeFormula(t *testing.T) {
	t.Parallel()
	a0, err := sampleScalar()
	require.NoError(t, err)
	k, err := sampleScalar()
	require.NoError(t, err)
	kCopy := edwards25519.NewScalar().Set(k)
	ctx := []byte("formula check")

	proofR, proofMu := dkgProveKnowledge(7, ctx, a0, k)
	require.Len(t, proofR, ElementLen)
	require.Len(t, proofMu, ScalarLen)

	// R_i = k·B
	assert.Equal(t, edwards25519.NewGeneratorPoint().ScalarBaseMult(kCopy).Bytes(), proofR)
	// c_i = H(i, Φ, φ_i0, R_i), μ_i = k + a_i0·c_i
	phi0 := edwards25519.NewGeneratorPoint().ScalarBaseMult(a0).Bytes()
	c := hashDKGProof(7, ctx, phi0, proofR)
	mu := edwards25519.NewScalar().Multiply(a0, c)
	mu.Add(mu, kCopy)
	assert.Equal(t, mu.Bytes(), proofMu)

	// k is zeroized after use.
	assert.Equal(t, 1, k.Equal(edwards25519.NewScalar()), "proof nonce k must be zeroized")

	// Verifies under the same (i, Φ, φ_i0).
	r1 := &DKGRound1Output{FeldmanCommitments: [][]byte{phi0}, ProofR: proofR, ProofMu: proofMu}
	require.NoError(t, dkgVerifyKnowledge(7, ctx, r1))
	// Not under another identifier or context.
	assert.Error(t, dkgVerifyKnowledge(8, ctx, r1))
	assert.Error(t, dkgVerifyKnowledge(7, []byte("other"), r1))
}

// TestDKGProofHashDomain checks the DKG proof hash is domain separated from
// the RFC 9591 hashes and depends on every input.
func TestDKGProofHashDomain(t *testing.T) {
	t.Parallel()
	ctx := []byte("ctx")
	phi0 := edwards25519.NewGeneratorPoint().Bytes()
	R := edwards25519.NewGeneratorPoint().ScalarBaseMult(scalarFromUint64(2)).Bytes()

	base := hashDKGProof(1, ctx, phi0, R)
	assert.Equal(t, base.Bytes(), hashDKGProof(1, ctx, phi0, R).Bytes(), "deterministic")
	assert.NotEqual(t, base.Bytes(), hashDKGProof(2, ctx, phi0, R).Bytes(), "identifier")
	assert.NotEqual(t, base.Bytes(), hashDKGProof(1, []byte("ctx2"), phi0, R).Bytes(), "context")
	assert.NotEqual(t, base.Bytes(), hashDKGProof(1, ctx, R, R).Bytes(), "phi0")
	assert.NotEqual(t, base.Bytes(), hashDKGProof(1, ctx, phi0, phi0).Bytes(), "R")

	// Same bytes through H1/H3 give a different scalar (domain tag "dkg").
	input := append(append(append(serializeScalarID(1), ctx...), phi0...), R...)
	assert.NotEqual(t, base.Bytes(), H1(input).Bytes())
	assert.NotEqual(t, base.Bytes(), H3(input).Bytes())
}

func TestDKGRound1ProofVerifies(t *testing.T) {
	t.Parallel()
	s := runDKGRound1(t, []int{1, 2, 3}, 2)
	for _, id := range s.allIDs {
		out := s.r1[id]
		assert.Len(t, out.ProofR, ElementLen)
		assert.Len(t, out.ProofMu, ScalarLen)
		assert.NoError(t, dkgVerifyKnowledge(id, dkgTestContext, out), "party %d", id)
		assert.Error(t, dkgVerifyKnowledge(id, []byte("another session"), out), "party %d under another context", id)
	}
}

func TestDKGProofWrongMu(t *testing.T) {
	t.Parallel()
	s := runDKGRound1(t, []int{1, 2, 3}, 2)
	runDKGRound2(t, s)

	wrong, err := sampleScalar()
	require.NoError(t, err)
	s.r1[2].ProofMu = wrong.Bytes()
	requireRound2AndFinalizeReject(t, s, 1, 2)
	requireRound2AndFinalizeReject(t, s, 3, 2)
}

func TestDKGProofWrongR(t *testing.T) {
	t.Parallel()
	s := runDKGRound1(t, []int{1, 2, 3}, 2)
	runDKGRound2(t, s)

	wrong, err := sampleScalar()
	require.NoError(t, err)
	s.r1[2].ProofR = edwards25519.NewGeneratorPoint().ScalarBaseMult(wrong).Bytes()
	requireRound2AndFinalizeReject(t, s, 1, 2)
}

// TestDKGProofForDifferentPhi0 is the rogue-key attack of the FROST paper:
// after seeing φ_{1,0}, P2 publishes φ_{2,0} = Y − φ_{1,0} for a Y whose
// discrete log it knows, so that the group key becomes Y. P2 cannot prove
// knowledge of log(φ_{2,0}); its genuine proof for its original φ_{2,0} and a
// made-up (R, μ) are both rejected before any share is sent to it.
func TestDKGProofForDifferentPhi0(t *testing.T) {
	t.Parallel()
	s := runDKGRound1(t, []int{1, 2}, 2)
	runDKGRound2(t, s)

	y, err := sampleScalar()
	require.NoError(t, err)
	Y := edwards25519.NewGeneratorPoint().ScalarBaseMult(y)
	phi10, err := deserializeElement(s.r1[1].FeldmanCommitments[0])
	require.NoError(t, err)
	rogue := edwards25519.NewIdentityPoint().Subtract(Y, phi10)

	// Keep P2's own valid proof, swap in the rogue commitment.
	s.r1[2].FeldmanCommitments[0] = rogue.Bytes()
	requireRound2AndFinalizeReject(t, s, 1, 2)

	// Forge a fresh (R, μ) for the rogue commitment: without log(rogue) the
	// verification equation R == μ·B − c·φ cannot be satisfied.
	k, err := sampleScalar()
	require.NoError(t, err)
	mu, err := sampleScalar()
	require.NoError(t, err)
	s.r1[2].ProofR = edwards25519.NewGeneratorPoint().ScalarBaseMult(k).Bytes()
	s.r1[2].ProofMu = mu.Bytes()
	requireRound2AndFinalizeReject(t, s, 1, 2)

	// The honest party's proof still verifies: the only bad party is 2.
	assert.NoError(t, dkgVerifyKnowledge(1, dkgTestContext, s.r1[1]))
}

// TestDKGProofReplayUnderDifferentContext: a round 1 message (with a valid
// proof) produced for one session context is rejected in a session with a
// different context, which is what Φ is for.
func TestDKGProofReplayUnderDifferentContext(t *testing.T) {
	t.Parallel()
	s := runDKGRound1(t, []int{1, 2, 3}, 2)
	runDKGRound2(t, s)

	otherCtx := []byte("a previous DKG session")
	cfg2 := s.configs[2]
	cfg2.Context = otherCtx
	replayed, _, err := DKGRound1(cfg2)
	require.NoError(t, err)
	require.NoError(t, dkgVerifyKnowledge(2, otherCtx, replayed), "valid in its own session")

	s.r1[2] = replayed
	requireRound2AndFinalizeReject(t, s, 1, 2)
	requireRound2AndFinalizeReject(t, s, 3, 2)
}

// TestDKGProofCopiedFromAnotherParty: P2 re-broadcasts P3's constant-term
// commitment together with P3's valid proof. The identifier is bound into
// c_i, so the copied proof does not verify for P2.
func TestDKGProofCopiedFromAnotherParty(t *testing.T) {
	t.Parallel()
	s := runDKGRound1(t, []int{1, 2, 3}, 2)
	runDKGRound2(t, s)

	s.r1[2].FeldmanCommitments[0] = s.r1[3].FeldmanCommitments[0]
	s.r1[2].ProofR = s.r1[3].ProofR
	s.r1[2].ProofMu = s.r1[3].ProofMu
	require.NoError(t, dkgVerifyKnowledge(3, dkgTestContext, s.r1[2]), "the copied proof is valid for party 3")
	requireRound2AndFinalizeReject(t, s, 1, 2)
}

func TestDKGProofMalformed(t *testing.T) {
	t.Parallel()
	s := runDKGRound1(t, []int{1, 2, 3}, 2)
	runDKGRound2(t, s)

	nonCanonicalMu := make([]byte, ScalarLen)
	for i := range nonCanonicalMu {
		nonCanonicalMu[i] = 0xff
	}
	cases := []struct {
		name   string
		tamper func(o *DKGRound1Output)
	}{
		{"short R", func(o *DKGRound1Output) { o.ProofR = o.ProofR[:31] }},
		{"missing R", func(o *DKGRound1Output) { o.ProofR = nil }},
		{"short mu", func(o *DKGRound1Output) { o.ProofMu = o.ProofMu[:31] }},
		{"missing mu", func(o *DKGRound1Output) { o.ProofMu = nil }},
		{"non-canonical mu", func(o *DKGRound1Output) { o.ProofMu = nonCanonicalMu }},
		{"no commitments", func(o *DKGRound1Output) { o.FeldmanCommitments = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tampered := roundTrip(t, "DKGRound1Output", s.r1[2])
			tc.tamper(tampered)
			r1 := map[int]*DKGRound1Output{1: s.r1[1], 2: tampered, 3: s.r1[3]}
			_, err := DKGRound2(s.configs[1], s.coeffs[1], r1)
			requireCheating(t, err, 2)
			_, err = DKGFinalize(s.configs[1], s.coeffs[1], r1, s.r2)
			requireCheating(t, err, 2)
		})
	}
}
