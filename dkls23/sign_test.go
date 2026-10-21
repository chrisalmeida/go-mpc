package dkls23

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/stretchr/testify/require"
)

// setupSigners runs DKG + pairwise base OT + FZero setup for all parties.
// Pairwise setup is parallelised across goroutines.
// For the common 3-of-3 case, prefer fullSetup() which caches the result.
func setupSigners(t testing.TB, allIDs []int, threshold int) map[int]*SignerSetup {
	t.Helper()
	setups, err := buildSetups(allIDs, threshold)
	require.NoError(t, err)
	return setups
}

// randomBools returns n random boolean values.
func randomBools(t *testing.T, n int) []bool {
	t.Helper()
	buf := make([]byte, (n+7)/8)
	_, err := rand.Read(buf)
	require.NoError(t, err)
	out := make([]bool, n)
	for k := 0; k < n; k++ {
		out[k] = (buf[k/8]>>(uint(k)%8))&1 == 1
	}
	return out
}

// computeRx reconstructs R = sum(R_j) from round2 states and returns the x-coordinate mod q.
func computeRx(t *testing.T, signers []int, round2States map[int]*Round2State) btcec.ModNScalar {
	t.Helper()
	return computeRxFromStates(signers, round2States)
}

// signingSession holds every message and state of one signing session so
// tests can inspect or tamper with them.
type signingSession struct {
	sigID    string
	signers  []int
	r1States map[int]*Round1State
	r1Msgs   map[int]map[int]*Round1Msg
	r2States map[int]*Round2State
	r2Msgs   map[int]map[int]*Round2Msg
	r3Frags  map[int]map[int]*Round3Msg
}

func (s *signingSession) round1For(myID int) map[int]*Round1Msg {
	m := make(map[int]*Round1Msg)
	for _, j := range s.signers {
		if j != myID {
			m[j] = s.r1Msgs[j][myID]
		}
	}
	return m
}

func (s *signingSession) round2For(myID int) map[int]*Round2Msg {
	m := make(map[int]*Round2Msg)
	for _, j := range s.signers {
		if j != myID {
			m[j] = s.r2Msgs[j][myID]
		}
	}
	return m
}

// runRound1 runs round 1 for all signers.
func runRound1(t *testing.T, setups map[int]*SignerSetup, sigID string, signers []int) *signingSession {
	t.Helper()
	s := &signingSession{
		sigID:    sigID,
		signers:  signers,
		r1States: make(map[int]*Round1State),
		r1Msgs:   make(map[int]map[int]*Round1Msg),
	}
	for _, id := range signers {
		st, msgs, err := SignRound1(setups[id], sigID, signers)
		require.NoError(t, err, "SignRound1 party %d", id)
		s.r1States[id] = st
		s.r1Msgs[id] = msgs
	}
	return s
}

// runRound2 runs round 2 for all signers.
func runRound2(t *testing.T, setups map[int]*SignerSetup, s *signingSession) {
	t.Helper()
	s.r2States = make(map[int]*Round2State)
	s.r2Msgs = make(map[int]map[int]*Round2Msg)
	for _, id := range s.signers {
		st2, msgs, err := SignRound2(setups[id], s.r1States[id], s.round1For(id))
		require.NoError(t, err, "SignRound2 party %d", id)
		s.r2States[id] = st2
		s.r2Msgs[id] = msgs
	}
}

// runRound3 runs round 3 for all signers.
func runRound3(t *testing.T, setups map[int]*SignerSetup, s *signingSession, message []byte) {
	t.Helper()
	s.r3Frags = make(map[int]map[int]*Round3Msg)
	for _, id := range s.signers {
		frags, err := SignRound3(setups[id], s.r2States[id], message, s.round2For(id))
		require.NoError(t, err, "SignRound3 party %d", id)
		s.r3Frags[id] = frags
	}
}

// combine runs SignCombine from the point of view of signers[0].
func (s *signingSession) combine(t *testing.T, setups map[int]*SignerSetup, message []byte) (r, sig []byte) {
	t.Helper()
	combiner := s.signers[0]
	myFrag := s.r3Frags[combiner][combiner]
	var myW, myU btcec.ModNScalar
	myW.SetByteSlice(myFrag.W_i)
	myU.SetByteSlice(myFrag.U_i)

	rx := computeRx(t, s.signers, s.r2States)

	allRound3 := make(map[int]*Round3Msg)
	for _, j := range s.signers {
		if j != combiner {
			allRound3[j] = s.r3Frags[j][combiner]
		}
	}

	r, sig, err := SignCombine(setups[combiner], &rx, &myW, &myU, allRound3, message)
	require.NoError(t, err, "SignCombine")
	return r, sig
}

// runSession executes a complete 3-round signing session among signers.
func runSession(t *testing.T, setups map[int]*SignerSetup, sigID string, signers []int, message []byte) *signingSession {
	t.Helper()
	s := runRound1(t, setups, sigID, signers)
	runRound2(t, setups, s)
	runRound3(t, setups, s, message)
	return s
}

// runSigning executes a complete 3-round signing session among signers and returns (r, s).
// It calls t.Fatal on any error.
func runSigning(t *testing.T, setups map[int]*SignerSetup, signers []int, message []byte) (r, s []byte) {
	t.Helper()
	sigID := "test-sig-" + string(message[:min(4, len(message))])
	sess := runSession(t, setups, sigID, signers, message)
	return sess.combine(t, setups, message)
}

// verifyECDSA checks (r,s) against the master public key and message.
func verifyECDSA(t *testing.T, pubKeyBytes []byte, message, r, s []byte) {
	t.Helper()
	pubKey, err := btcec.ParsePubKey(pubKeyBytes)
	require.NoError(t, err)
	msgHash := sha256.Sum256(message)
	var rS, sS btcec.ModNScalar
	rS.SetByteSlice(r)
	sS.SetByteSlice(s)
	sig := ecdsa.NewSignature(&rS, &sS)
	require.True(t, sig.Verify(msgHash[:], pubKey), "signature must verify")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestSign3of3(t *testing.T) {
	t.Parallel()
	allIDs := []int{1, 2, 3}
	setups := fullSetup(t)

	message := []byte("hello threshold ecdsa world!")
	r, s := runSigning(t, setups, allIDs, message)
	require.Len(t, r, 32)
	require.Len(t, s, 32)

	verifyECDSA(t, setups[1].PubKey, message, r, s)
}

func TestSign3of3MultipleMessages(t *testing.T) {
	t.Parallel()
	allIDs := []int{1, 2, 3}
	setups := fullSetup(t)

	for i := 0; i < 2; i++ {
		msg := []byte{byte(i), 0x42, 0xde, 0xad}
		r, s := runSigning(t, setups, allIDs, msg)
		verifyECDSA(t, setups[1].PubKey, msg, r, s)
	}
}

// TestSignSessionsUseFreshVOLE is the regression test for the audit finding
// that reused the same VOLE correlation across signing sessions: the
// difference of Alice's VOLE messages across two sessions must NOT equal the
// difference of her nonces, and Bob's OT-extension messages must differ.
func TestSignSessionsUseFreshVOLE(t *testing.T) {
	t.Parallel()
	setups := setupSigners(t, []int{1, 2}, 2)
	signers := []int{1, 2}

	s1 := runSession(t, setups, "session-1", signers, []byte("pay alice 1 BTC"))
	s2 := runSession(t, setups, "session-2", signers, []byte("pay alice 2 BTC"))

	// Both signatures are valid.
	r1, sig1 := s1.combine(t, setups, []byte("pay alice 1 BTC"))
	verifyECDSA(t, setups[1].PubKey, []byte("pay alice 1 BTC"), r1, sig1)
	r2, sig2 := s2.combine(t, setups, []byte("pay alice 2 BTC"))
	verifyECDSA(t, setups[1].PubKey, []byte("pay alice 2 BTC"), r2, sig2)

	// Party 1 → party 2 VOLE messages in the two sessions.
	var a1, a2, leaked btcec.ModNScalar
	a1.SetByteSlice(s1.r2Msgs[1][2].VoleMsg.ATilde[0][0][:])
	a2.SetByteSlice(s2.r2Msgs[1][2].VoleMsg.ATilde[0][0][:])
	leaked.NegateVal(&a1)
	leaked.Add(&a2)

	var trueDelta btcec.ModNScalar
	trueDelta.NegateVal(&s1.r1States[1].R_i)
	trueDelta.Add(&s2.r1States[1].R_i)
	require.False(t, leaked.Equals(&trueDelta), "VOLE message difference must not reveal the nonce difference")

	// Bob's per-session OT-extension batches are fresh.
	require.NotEqual(t, s1.r1Msgs[2][1].OTExt.U, s2.r1Msgs[2][1].OTExt.U, "OT-extension batch must be fresh per session")
	require.NotEqual(t, s1.r1States[2].VoleBobForRound2[1].Beta, s2.r1States[2].VoleBobForRound2[1].Beta, "VOLE beta must be fresh per session")
}

func TestSignBadRCommitment(t *testing.T) {
	t.Parallel()
	// A party that sends a bad round-1 commitment must be detected in round 3.
	setups := fullSetup(t)
	signers := []int{1, 2, 3}
	message := []byte("bad commitment test message!!")

	s := runRound1(t, setups, "test-bad-commit", signers)

	// Party 2 corrupts its commitment sent to all other parties.
	for _, j := range signers {
		if j != 2 {
			s.r1Msgs[2][j].Commitment[0] ^= 0xff
		}
	}

	runRound2(t, setups, s)

	// Parties 1 and 3 must detect bad decommitment from party 2 in round 3.
	for _, id := range []int{1, 3} {
		_, err := SignRound3(setups[id], s.r2States[id], message, s.round2For(id))
		require.Error(t, err, "party %d must detect bad R commitment from party 2", id)
		var cheat *CheatingPartyError
		require.True(t, errors.As(err, &cheat))
		require.Equal(t, []int{2}, cheat.PartyIDs)
		require.True(t, setups[id].Blacklist[2])
	}
}

// TestSignBadOTExtension: a Bob who sends an inconsistent OT-extension batch
// is caught by Alice's consistency check in round 2 and blacklisted.
func TestSignBadOTExtension(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	signers := []int{1, 2, 3}

	s := runRound1(t, setups, "test-bad-ote", signers)

	// Party 2 tampers with the batch it sent to party 1 (party 2 is Bob for
	// the 1→2 VOLE direction).
	s.r1Msgs[2][1].OTExt.XBar[0] ^= 0x01

	_, _, err := SignRound2(setups[1], s.r1States[1], s.round1For(1))
	require.Error(t, err)
	var cheat *CheatingPartyError
	require.True(t, errors.As(err, &cheat))
	require.Equal(t, []int{2}, cheat.PartyIDs)
	require.True(t, setups[1].Blacklist[2], "party 2 must be blacklisted at party 1")

	// Party 3 did not receive the tampered message and proceeds normally.
	_, _, err = SignRound2(setups[3], s.r1States[3], s.round1For(3))
	require.NoError(t, err)

	// Party 1 refuses future sessions with party 2.
	_, _, err = SignRound1(setups[1], "later-session", signers)
	var bl *BlacklistedPartyError
	require.True(t, errors.As(err, &bl))
	require.Equal(t, []int{2}, bl.PartyIDs)
}

func TestSignRound2MissingRound1Message(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	signers := []int{1, 2, 3}
	s := runRound1(t, setups, "test-missing-r1", signers)

	in := s.round1For(1)
	delete(in, 3)
	_, _, err := SignRound2(setups[1], s.r1States[1], in)
	require.Error(t, err)
	var inputErr *InvalidInputError
	require.True(t, errors.As(err, &inputErr))
	require.Contains(t, inputErr.Detail, "party 3")

	in = s.round1For(1)
	in[3] = &Round1Msg{Commitment: in[3].Commitment} // no OT-extension payload
	_, _, err = SignRound2(setups[1], s.r1States[1], in)
	require.Error(t, err)
	require.True(t, errors.As(err, &inputErr))
}

func TestSignRound1MissingBaseOT(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	delete(setups[1].BobBaseOT, 2)
	_, _, err := SignRound1(setups[1], "test-missing-base-ot", []int{1, 2, 3})
	require.Error(t, err)
	var corrupt *CorruptStateError
	require.True(t, errors.As(err, &corrupt))
	require.Contains(t, corrupt.Detail, "party 2")
}

func TestSignRound2MissingBaseOT(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	signers := []int{1, 2, 3}
	s := runRound1(t, setups, "test-missing-alice-base-ot", signers)
	delete(setups[1].AliceBaseOT, 2)
	_, _, err := SignRound2(setups[1], s.r1States[1], s.round1For(1))
	require.Error(t, err)
	var corrupt *CorruptStateError
	require.True(t, errors.As(err, &corrupt))
	require.Contains(t, corrupt.Detail, "party 2")
}

func TestComputeRxFromDecommitments(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	signers := []int{1, 2, 3}

	s := runRound1(t, setups, "compute-rx-test", signers)
	runRound2(t, setups, s)

	// Compute rx the local way: from Round2State.R_iPoint
	rxOld := computeRxFromStates(signers, s.r2States)

	// Compute rx from decommitments (the distributed pattern)
	noncePoints := map[int][]byte{
		1: s.r2States[1].R_iPoint,
		2: s.r2Msgs[2][1].Decommitment,
		3: s.r2Msgs[3][1].Decommitment,
	}
	rxNew, err := ComputeRx(noncePoints)
	require.NoError(t, err)
	require.True(t, rxOld.Equals(&rxNew), "rx from decommitments must match rx from states")

	// Verify node 2's view produces the same rx
	noncePoints2 := map[int][]byte{
		1: s.r2Msgs[1][2].Decommitment,
		2: s.r2States[2].R_iPoint,
		3: s.r2Msgs[3][2].Decommitment,
	}
	rxNode2, err := ComputeRx(noncePoints2)
	require.NoError(t, err)
	require.True(t, rxOld.Equals(&rxNode2), "all nodes must compute the same rx")
}

func TestComputeRxUsedInSignCombine(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	msg := []byte("ComputeRx end-to-end test")
	signers := []int{1, 2, 3}

	s := runSession(t, setups, "rx-e2e-test", signers, msg)

	noncePoints := map[int][]byte{
		1: s.r2States[1].R_iPoint,
		2: s.r2Msgs[2][1].Decommitment,
		3: s.r2Msgs[3][1].Decommitment,
	}
	rx, err := ComputeRx(noncePoints)
	require.NoError(t, err)

	myFrag := s.r3Frags[1][1]
	var myW, myU btcec.ModNScalar
	myW.SetByteSlice(myFrag.W_i)
	myU.SetByteSlice(myFrag.U_i)
	allFrags := map[int]*Round3Msg{}
	for _, j := range signers {
		if j != 1 {
			allFrags[j] = s.r3Frags[j][1]
		}
	}
	r, sig, err := SignCombine(setups[1], &rx, &myW, &myU, allFrags, msg)
	require.NoError(t, err)
	verifyECDSA(t, setups[1].PubKey, msg, r, sig)
}

// TestSignCombineIgnoresOwnFragment: passing SignRound3's full output map
// (which includes the caller's own fragment) must not double count it.
func TestSignCombineIgnoresOwnFragment(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	msg := []byte("own fragment test")
	signers := []int{1, 2, 3}

	s := runSession(t, setups, "own-frag-test", signers, msg)

	myFrag := s.r3Frags[1][1]
	var myW, myU btcec.ModNScalar
	myW.SetByteSlice(myFrag.W_i)
	myU.SetByteSlice(myFrag.U_i)
	rx := computeRxFromStates(signers, s.r2States)

	allFrags := map[int]*Round3Msg{1: s.r3Frags[1][1], 2: s.r3Frags[2][1], 3: s.r3Frags[3][1], 4: nil}
	r, sig, err := SignCombine(setups[1], &rx, &myW, &myU, allFrags, msg)
	require.NoError(t, err)
	verifyECDSA(t, setups[1].PubKey, msg, r, sig)
}

func TestSignCombineBadFragment(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	msg := []byte("bad fragment test")
	signers := []int{1, 2, 3}

	s := runSession(t, setups, "bad-frag-test", signers, msg)

	myFrag := s.r3Frags[1][1]
	var myW, myU btcec.ModNScalar
	myW.SetByteSlice(myFrag.W_i)
	myU.SetByteSlice(myFrag.U_i)
	rx := computeRxFromStates(signers, s.r2States)

	bad := &Round3Msg{W_i: make([]byte, 32), U_i: make([]byte, 32)}
	copy(bad.W_i, s.r3Frags[2][1].W_i)
	copy(bad.U_i, s.r3Frags[2][1].U_i)
	bad.W_i[0] ^= 0x01
	allFrags := map[int]*Round3Msg{2: bad, 3: s.r3Frags[3][1]}
	_, _, err := SignCombine(setups[1], &rx, &myW, &myU, allFrags, msg)
	require.Error(t, err, "final signature verification must fail")
	require.Contains(t, err.Error(), "verification failed")
}

func TestComputeRxEmpty(t *testing.T) {
	_, err := ComputeRx(map[int][]byte{})
	require.Error(t, err)
	var inputErr *InvalidInputError
	require.True(t, errors.As(err, &inputErr))
	require.Contains(t, inputErr.Detail, "no nonce points")
}

func TestComputeRxNil(t *testing.T) {
	_, err := ComputeRx(nil)
	require.Error(t, err)
}

func TestComputeRxBadPoint(t *testing.T) {
	_, err := ComputeRx(map[int][]byte{1: {0xff, 0xff}})
	require.Error(t, err)
	var inputErr *InvalidInputError
	require.True(t, errors.As(err, &inputErr))
	require.Contains(t, inputErr.Detail, "party 1")
}

func TestComputeRxSinglePoint(t *testing.T) {
	var scalar btcec.ModNScalar
	scalar.SetInt(42)
	compressed, err := scalarMulGCompressed(&scalar)
	require.NoError(t, err)

	rx, err := ComputeRx(map[int][]byte{1: compressed})
	require.NoError(t, err)

	var pt btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(&scalar, &pt)
	pt.ToAffine()
	expected := make([]byte, 32)
	pt.X.PutBytesUnchecked(expected)
	var expectedRx btcec.ModNScalar
	expectedRx.SetByteSlice(expected)
	require.True(t, rx.Equals(&expectedRx))
}

func TestSignBadVOLEMessage(t *testing.T) {
	t.Parallel()
	// A party that sends a bad VOLE multiply message must be detected in round 3.
	setups := fullSetup(t)
	signers := []int{1, 2, 3}
	message := []byte("bad vole test message!!!!!!!!")

	s := runRound1(t, setups, "test-bad-vole", signers)
	runRound2(t, setups, s)

	// Party 2 tampers its VOLE multiply message addressed to party 1.
	s.r2Msgs[2][1].VoleMsg.ATilde[0][0][0] ^= 0xff

	// Party 1 must detect party 2's bad VOLE message.
	_, err := SignRound3(setups[1], s.r2States[1], message, s.round2For(1))
	require.Error(t, err, "party 1 must detect bad VOLE message from party 2")
	var cheat *CheatingPartyError
	require.True(t, errors.As(err, &cheat))
	require.Equal(t, []int{2}, cheat.PartyIDs)
}

// TestSignRound3RejectsMalformedCheckValues: every round 2 field that round 3
// parses (Γ^u, Γ^v, pk_i, the decommitted R_j) is replaced in turn with a
// wrong or unparseable value; the sender must be identified and blacklisted.
func TestSignRound3RejectsMalformedCheckValues(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	signers := []int{1, 2, 3}
	message := []byte("bad gamma test")

	s := runRound1(t, setups, "test-bad-gamma", signers)
	runRound2(t, setups, s)

	cases := []struct {
		name   string
		tamper func(m *Round2Msg)
	}{
		{"gamma_u", func(m *Round2Msg) { m.GammaU[1] ^= 0xff }},
		{"gamma_v", func(m *Round2Msg) { m.GammaV[1] ^= 0xff }},
		{"pki invalid", func(m *Round2Msg) { m.PKi = []byte{0x00} }},
		{"gamma_u invalid", func(m *Round2Msg) { m.GammaU = []byte{0x00} }},
		{"gamma_v invalid", func(m *Round2Msg) { m.GammaV = []byte{0x00} }},
		{"decommit invalid", func(m *Round2Msg) { m.Decommitment = []byte{0x00} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Fresh copies of party 1's setup so blacklisting does not leak across cases.
			local := fullSetup(t)
			in := s.round2For(1)
			orig := *in[2]
			tampered := orig
			if orig.GammaU != nil {
				tampered.GammaU = append([]byte(nil), orig.GammaU...)
				tampered.GammaV = append([]byte(nil), orig.GammaV...)
				tampered.PKi = append([]byte(nil), orig.PKi...)
				tampered.Decommitment = append([]byte(nil), orig.Decommitment...)
			}
			tc.tamper(&tampered)
			in[2] = &tampered
			// Party 1's round 2 state belongs to setups[1]; its Share and PubKey
			// are identical in local[1] (same cached fixture).
			_, err := SignRound3(local[1], s.r2States[1], message, in)
			require.Error(t, err)
			var cheat *CheatingPartyError
			require.True(t, errors.As(err, &cheat), "got %v", err)
			require.Equal(t, []int{2}, cheat.PartyIDs)
		})
	}
}

func TestSignRound3MissingMessage(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	signers := []int{1, 2, 3}
	message := []byte("missing round 2 message")

	s := runRound1(t, setups, "test-missing-r2", signers)
	runRound2(t, setups, s)

	in := s.round2For(1)
	delete(in, 3)
	_, err := SignRound3(setups[1], s.r2States[1], message, in)
	require.Error(t, err)
	var cheat *CheatingPartyError
	require.True(t, errors.As(err, &cheat))
	require.Equal(t, []int{3}, cheat.PartyIDs)
}

func TestSignRound1BelowThreshold(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	_, _, err := SignRound1(setups[1], "test", []int{1, 2})
	require.Error(t, err)
	var inputErr *InvalidInputError
	require.True(t, errors.As(err, &inputErr))
	require.Contains(t, inputErr.Detail, "below threshold")
}

func TestSignRound1MyIDNotInSigners(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	_, _, err := SignRound1(setups[1], "test", []int{2, 3, 4})
	require.Error(t, err)
	var inputErr *InvalidInputError
	require.True(t, errors.As(err, &inputErr))
	require.Contains(t, inputErr.Detail, "myID not in signers")
}

func TestSignRound1DuplicateSigners(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	_, _, err := SignRound1(setups[1], "test", []int{1, 1, 2, 3})
	require.Error(t, err)
	var inputErr *InvalidInputError
	require.True(t, errors.As(err, &inputErr))
	require.Contains(t, inputErr.Detail, "duplicate")
}

func TestSignNilVoleBobState(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	signers := []int{1, 2, 3}

	s := runRound1(t, setups, "nil-vole-test", signers)
	s.r1States[1].VoleBobForRound2[2] = nil

	_, _, err := SignRound2(setups[1], s.r1States[1], s.round1For(1))
	require.Error(t, err, "should detect nil VOLE Bob state without panic")
	var corruptErr *CorruptStateError
	require.True(t, errors.As(err, &corruptErr))
	require.Contains(t, corruptErr.Detail, "missing VOLE Bob state")
}

func TestSignBlacklistedPartyRejectedEverywhere(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	signers := []int{1, 2, 3}
	s := runRound1(t, setups, "blacklist-test", signers)
	runRound2(t, setups, s)

	setups[1].Blacklist[3] = true
	var bl *BlacklistedPartyError

	_, _, err := SignRound1(setups[1], "x", signers)
	require.True(t, errors.As(err, &bl))
	_, _, err = SignRound2(setups[1], s.r1States[1], s.round1For(1))
	require.True(t, errors.As(err, &bl))
	_, err = SignRound3(setups[1], s.r2States[1], []byte("m"), s.round2For(1))
	require.True(t, errors.As(err, &bl))
}
