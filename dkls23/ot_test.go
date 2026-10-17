package dkls23

import (
	"crypto/rand"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

// runBaseOTWithChoices runs one complete base OT (receiver round 1 → sender
// round 2 → receiver finalize) for the given choice bits and returns every
// artefact so tests can inspect messages and state.
func runBaseOTWithChoices(t *testing.T, choices []bool) (
	recvSeeds, seeds0, seeds1 [][]byte,
	msg *BaseOTReceiverMsg, reply *BaseOTSenderMsg, state *BaseOTReceiverState,
) {
	t.Helper()
	state, msg, err := BaseOTReceiverRound1(choices)
	require.NoError(t, err)
	seeds0, seeds1, reply, err = BaseOTSenderRound2(msg)
	require.NoError(t, err)
	recvSeeds, err = BaseOTReceiverFinalize(state, reply)
	require.NoError(t, err)
	return recvSeeds, seeds0, seeds1, msg, reply, state
}

// assertBaseOTCorrect checks recv[k] == seeds_{c_k}[k] and recv[k] != seeds_{1-c_k}[k]
// for every instance k, and that every seed is 32 bytes.
func assertBaseOTCorrect(t *testing.T, choices []bool, recv, seeds0, seeds1 [][]byte) {
	t.Helper()
	n := len(choices)
	require.Len(t, recv, n)
	require.Len(t, seeds0, n)
	require.Len(t, seeds1, n)
	for k := 0; k < n; k++ {
		require.Len(t, recv[k], 32, "k=%d", k)
		require.Len(t, seeds0[k], 32, "k=%d", k)
		require.Len(t, seeds1[k], 32, "k=%d", k)
		require.NotEqual(t, seeds0[k], seeds1[k], "sender seeds must differ at k=%d", k)
		if choices[k] {
			require.Equal(t, seeds1[k], recv[k], "OT seed mismatch at k=%d (choice=true)", k)
			require.NotEqual(t, seeds0[k], recv[k], "receiver must not learn K^0 at k=%d", k)
		} else {
			require.Equal(t, seeds0[k], recv[k], "OT seed mismatch at k=%d (choice=false)", k)
			require.NotEqual(t, seeds1[k], recv[k], "receiver must not learn K^1 at k=%d", k)
		}
	}
}

// assertValidDistinctPoints checks that a and b are both valid 33-byte
// compressed points and are distinct.
func assertValidDistinctPoints(t *testing.T, name string, k int, a, b []byte) {
	t.Helper()
	require.Len(t, a, compressedPointLen, "%s_0 length at k=%d", name, k)
	require.Len(t, b, compressedPointLen, "%s_1 length at k=%d", name, k)
	_, err := compressedToPoint(a)
	require.NoError(t, err, "%s_0 must be a valid point at k=%d", name, k)
	_, err = compressedToPoint(b)
	require.NoError(t, err, "%s_1 must be a valid point at k=%d", name, k)
	require.NotEqual(t, a, b, "%s_0 and %s_1 must be distinct at k=%d", name, name, k)
}

func TestBaseOT(t *testing.T) {
	t.Parallel()
	choices := randomBools(t, LambdaC)
	input := append([]bool(nil), choices...)

	recv, seeds0, seeds1, msg, reply, state := runBaseOTWithChoices(t, input)
	assertBaseOTCorrect(t, choices, recv, seeds0, seeds1)

	// Both messages carry LambdaC pairs of distinct, valid compressed points.
	require.Len(t, msg.R0, LambdaC)
	require.Len(t, msg.R1, LambdaC)
	require.Len(t, reply.M0, LambdaC)
	require.Len(t, reply.M1, LambdaC)
	for k := 0; k < LambdaC; k++ {
		assertValidDistinctPoints(t, "r", k, msg.R0[k], msg.R1[k])
		assertValidDistinctPoints(t, "m", k, reply.M0[k], reply.M1[k])
	}

	// Seeds are unique across instances and across the two strings (the
	// derivation is domain-separated by k).
	seen := make(map[string]int, 2*LambdaC)
	for k := 0; k < LambdaC; k++ {
		seen[string(seeds0[k])]++
		seen[string(seeds1[k])]++
	}
	require.Len(t, seen, 2*LambdaC, "all sender seeds must be distinct")

	// The receiver's ephemeral scalars are zeroized by finalize and the state
	// cannot be finalized a second time.
	require.Len(t, state.A, LambdaC)
	for k := range state.A {
		require.True(t, state.A[k].IsZero(), "a_%d must be zeroized after finalize", k)
	}
	_, err := BaseOTReceiverFinalize(state, reply)
	require.Error(t, err)
	require.Contains(t, err.Error(), "zeroized")

	// The state holds a private copy of the choice bits: the caller's slice is
	// untouched by Zero, and the copy is cleared.
	require.Equal(t, choices, state.Choices)
	state.Zero()
	require.Equal(t, choices, input, "caller's choice slice must not be modified")
	for k, c := range state.Choices {
		require.False(t, c, "choice %d must be cleared by Zero", k)
	}
}

func TestBaseOTBothChoiceValues(t *testing.T) {
	t.Parallel()
	const n = 8
	patterns := map[string]func(k int) bool{
		"all-false":   func(int) bool { return false },
		"all-true":    func(int) bool { return true },
		"alternating": func(k int) bool { return k%2 == 1 },
	}
	for name, pattern := range patterns {
		choices := make([]bool, n)
		for k := range choices {
			choices[k] = pattern(k)
		}
		recv, seeds0, seeds1, _, _, _ := runBaseOTWithChoices(t, choices)
		assertBaseOTCorrect(t, choices, recv, seeds0, seeds1)
		t.Logf("pattern %s ok", name)
	}
}

func TestBaseOTReceiverMsgIsIndependentOfChoice(t *testing.T) {
	t.Parallel()
	// Receiver security is endemic: regardless of the choice bit both r_0 and
	// r_1 are valid, distinct points and nothing in the message is a fixed
	// function of c. This is a sanity check, not a distinguishing test.
	for _, c := range []bool{false, true} {
		state, msg, err := BaseOTReceiverRound1([]bool{c, c, c})
		require.NoError(t, err)
		defer state.Zero()
		for k := range msg.R0 {
			assertValidDistinctPoints(t, "r", k, msg.R0[k], msg.R1[k])
		}
		// Two runs with the same choice bits yield different messages
		// (fresh randomness every time).
		state2, msg2, err := BaseOTReceiverRound1([]bool{c, c, c})
		require.NoError(t, err)
		defer state2.Zero()
		require.NotEqual(t, msg.R0, msg2.R0)
		require.NotEqual(t, msg.R1, msg2.R1)
	}
}

// notOnCurveEncoding returns a 33-byte compressed encoding whose x-coordinate
// is in range but not on secp256k1.
func notOnCurveEncoding(t *testing.T) []byte {
	t.Helper()
	for x := byte(1); x < 255; x++ {
		enc := make([]byte, compressedPointLen)
		enc[0] = compressedEvenPrefix
		enc[compressedPointLen-1] = x
		if _, err := compressedToPoint(enc); err != nil {
			return enc
		}
	}
	t.Fatal("no small off-curve x-coordinate found")
	return nil
}

// badPointEncodings returns a set of malformed replacements for a valid
// compressed point, each labelled.
func badPointEncodings(t *testing.T, valid []byte) map[string][]byte {
	t.Helper()
	tooLong := append(append([]byte{}, valid...), 0x00)
	wrongPrefix := append([]byte{0x04}, valid[1:]...)
	xTooBig := append([]byte{compressedEvenPrefix}, make([]byte, 32)...)
	for i := 1; i < compressedPointLen; i++ {
		xTooBig[i] = 0xff // x = 2^256-1 >= p
	}
	return map[string][]byte{
		"nil":          nil,
		"empty":        {},
		"too short":    valid[:compressedPointLen-1],
		"too long":     tooLong,
		"wrong prefix": wrongPrefix,
		"x >= p":       xTooBig,
		"not on curve": notOnCurveEncoding(t),
	}
}

func cloneReceiverMsg(m *BaseOTReceiverMsg) *BaseOTReceiverMsg {
	out := &BaseOTReceiverMsg{R0: make([][]byte, len(m.R0)), R1: make([][]byte, len(m.R1))}
	copy(out.R0, m.R0)
	copy(out.R1, m.R1)
	return out
}

func cloneSenderMsg(m *BaseOTSenderMsg) *BaseOTSenderMsg {
	out := &BaseOTSenderMsg{M0: make([][]byte, len(m.M0)), M1: make([][]byte, len(m.M1))}
	copy(out.M0, m.M0)
	copy(out.M1, m.M1)
	return out
}

func TestBaseOTReceiverRound1RejectsEmptyChoices(t *testing.T) {
	t.Parallel()
	for _, choices := range [][]bool{nil, {}} {
		state, msg, err := BaseOTReceiverRound1(choices)
		require.Error(t, err)
		require.Nil(t, state)
		require.Nil(t, msg)
	}
}

func TestBaseOTSenderRound2MalformedMessages(t *testing.T) {
	t.Parallel()
	const n = 4
	state, msg, err := BaseOTReceiverRound1(randomBools(t, n))
	require.NoError(t, err)
	defer state.Zero()

	expectSenderError := func(name string, m *BaseOTReceiverMsg) {
		t.Helper()
		require.NotPanics(t, func() {
			seeds0, seeds1, reply, err := BaseOTSenderRound2(m)
			require.Error(t, err, name)
			require.Nil(t, seeds0, name)
			require.Nil(t, seeds1, name)
			require.Nil(t, reply, name)
		}, name)
	}

	expectSenderError("nil message", nil)
	expectSenderError("empty message", &BaseOTReceiverMsg{})
	expectSenderError("empty slices", &BaseOTReceiverMsg{R0: [][]byte{}, R1: [][]byte{}})
	expectSenderError("r1 shorter", &BaseOTReceiverMsg{R0: msg.R0, R1: msg.R1[:n-1]})
	expectSenderError("r0 shorter", &BaseOTReceiverMsg{R0: msg.R0[:n-1], R1: msg.R1})
	expectSenderError("r1 missing", &BaseOTReceiverMsg{R0: msg.R0})

	for name, bad := range badPointEncodings(t, msg.R0[0]) {
		tampered := cloneReceiverMsg(msg)
		tampered.R0[2] = bad
		expectSenderError("r_0 "+name, tampered)

		tampered = cloneReceiverMsg(msg)
		tampered.R1[1] = bad
		expectSenderError("r_1 "+name, tampered)
	}

	// The untampered message is still accepted.
	_, _, _, err = BaseOTSenderRound2(msg)
	require.NoError(t, err)
}

func TestBaseOTReceiverFinalizeMalformedMessages(t *testing.T) {
	t.Parallel()
	const n = 4
	choices := randomBools(t, n)
	freshState := func() (*BaseOTReceiverState, *BaseOTSenderMsg) {
		t.Helper()
		state, msg, err := BaseOTReceiverRound1(choices)
		require.NoError(t, err)
		_, _, reply, err := BaseOTSenderRound2(msg)
		require.NoError(t, err)
		return state, reply
	}

	expectFinalizeError := func(name string, state *BaseOTReceiverState, reply *BaseOTSenderMsg) {
		t.Helper()
		require.NotPanics(t, func() {
			seeds, err := BaseOTReceiverFinalize(state, reply)
			require.Error(t, err, name)
			require.Nil(t, seeds, name)
		}, name)
		// Finalize zeroizes the scalars even on failure.
		if state != nil {
			for k := range state.A {
				require.True(t, state.A[k].IsZero(), "%s: a_%d must be zeroized", name, k)
			}
		}
	}

	_, reply := freshState()
	expectFinalizeError("nil state", nil, reply)

	state, _ := freshState()
	expectFinalizeError("nil reply", state, nil)

	state, _ = freshState()
	expectFinalizeError("empty reply", state, &BaseOTSenderMsg{})

	state, reply = freshState()
	expectFinalizeError("m1 shorter", state, &BaseOTSenderMsg{M0: reply.M0, M1: reply.M1[:n-1]})

	state, reply = freshState()
	expectFinalizeError("m0 shorter", state, &BaseOTSenderMsg{M0: reply.M0[:n-1], M1: reply.M1})

	state, reply = freshState()
	expectFinalizeError("too many points", state, &BaseOTSenderMsg{
		M0: append(append([][]byte{}, reply.M0...), reply.M0[0]),
		M1: append(append([][]byte{}, reply.M1...), reply.M1[0]),
	})

	expectFinalizeError("empty state", &BaseOTReceiverState{}, reply)
	expectFinalizeError("state with choices but no scalars", &BaseOTReceiverState{Choices: choices}, reply)
	expectFinalizeError("inconsistent state", &BaseOTReceiverState{
		Choices: choices,
		A:       make([]btcec.ModNScalar, n-1),
	}, reply)

	// A state whose scalars have been zeroized (already finalized or aborted)
	// cannot be finalized.
	state, reply = freshState()
	state.Zero()
	expectFinalizeError("zeroized state", state, reply)

	for name, bad := range badPointEncodings(t, reply.M0[0]) {
		state, reply = freshState()
		tampered := cloneSenderMsg(reply)
		tampered.M0[3] = bad
		expectFinalizeError("m_0 "+name, state, tampered)

		state, reply = freshState()
		tampered = cloneSenderMsg(reply)
		tampered.M1[0] = bad
		expectFinalizeError("m_1 "+name, state, tampered)
	}

	// Invalid m_{B,1-c} is rejected even though it is not the selected point:
	// validation never depends on the choice bit.
	for _, c := range []bool{false, true} {
		st, m, err := BaseOTReceiverRound1([]bool{c})
		require.NoError(t, err)
		_, _, rep, err := BaseOTSenderRound2(m)
		require.NoError(t, err)
		if c {
			rep.M0[0] = notOnCurveEncoding(t)
		} else {
			rep.M1[0] = notOnCurveEncoding(t)
		}
		expectFinalizeError("unselected point invalid", st, rep)
	}
}

func TestBaseOTSenderRejectsIdentityForcingMessage(t *testing.T) {
	t.Parallel()
	// A malicious receiver with c = 1 sets r_0 = −H_0(r_1) so that
	// m_{A,0} = O and s_{B,0} = O would be predictable without b_0; the sender
	// must abort instead of deriving K^0 from the identity.
	for k, choices := range [][]bool{{true}, {false, true}} {
		state, msg, err := BaseOTReceiverRound1(choices)
		require.NoError(t, err)
		defer state.Zero()
		last := len(choices) - 1
		negH0, err := pointToCompressed(pointNeg(hashToCurve(0, last, msg.R1[last])))
		require.NoError(t, err)
		msg.R0[last] = negH0
		_, _, _, err = BaseOTSenderRound2(msg)
		require.Error(t, err, "case %d", k)
		require.Contains(t, err.Error(), "point at infinity")
	}

	// Symmetric case for j = 1: r_1 = −H_1(r_0).
	state, msg, err := BaseOTReceiverRound1([]bool{false})
	require.NoError(t, err)
	defer state.Zero()
	negH1, err := pointToCompressed(pointNeg(hashToCurve(1, 0, msg.R0[0])))
	require.NoError(t, err)
	msg.R1[0] = negH1
	_, _, _, err = BaseOTSenderRound2(msg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "point at infinity")
}

func TestBaseOTSwappedReplyYieldsOtherSeed(t *testing.T) {
	t.Parallel()
	// Swapping m_{B,0} and m_{B,1} makes the receiver agree on the other key:
	// the seed is a function of the agreed Diffie-Hellman key, not of c alone.
	choices := []bool{false, true}
	state, msg, err := BaseOTReceiverRound1(choices)
	require.NoError(t, err)
	seeds0, seeds1, reply, err := BaseOTSenderRound2(msg)
	require.NoError(t, err)
	swapped := &BaseOTSenderMsg{M0: reply.M1, M1: reply.M0}
	recv, err := BaseOTReceiverFinalize(state, swapped)
	require.NoError(t, err)
	// With m_{B,1-c} the receiver computes a·b_{1-c}·G, which is neither
	// agreed key (s_{B,1-c} = b_{1-c}·m_{A,1-c} with m_{A,1-c} != a·G).
	for k := range choices {
		require.NotEqual(t, seeds0[k], recv[k], "k=%d", k)
		require.NotEqual(t, seeds1[k], recv[k], "k=%d", k)
	}
}

func TestHashToCurve(t *testing.T) {
	t.Parallel()
	input := make([]byte, compressedPointLen)
	_, err := rand.Read(input)
	require.NoError(t, err)
	other := append([]byte{}, input...)
	other[5] ^= 0x01

	p := hashToCurve(0, 0, input)
	require.False(t, isInfinity(p))
	pb, err := pointToCompressed(p)
	require.NoError(t, err)
	require.Equal(t, byte(compressedEvenPrefix), pb[0], "hash-to-curve output must have even y")

	// Deterministic.
	qb, err := pointToCompressed(hashToCurve(0, 0, input))
	require.NoError(t, err)
	require.Equal(t, pb, qb)

	// Domain separated by j, by k and by input.
	variants := map[string]*btcec.JacobianPoint{
		"j=1":         hashToCurve(1, 0, input),
		"k=1":         hashToCurve(0, 1, input),
		"other input": hashToCurve(0, 0, other),
	}
	seen := map[string]string{string(pb): "base"}
	for name, v := range variants {
		vb, err := pointToCompressed(v)
		require.NoError(t, err)
		require.Equal(t, byte(compressedEvenPrefix), vb[0], name)
		prev, dup := seen[string(vb)]
		require.False(t, dup, "%s collides with %s", name, prev)
		seen[string(vb)] = name
	}

	// Many inputs: every output is a valid point (the trial loop terminates
	// and never yields an off-curve or infinite result).
	for i := 0; i < 64; i++ {
		_, err := rand.Read(input)
		require.NoError(t, err)
		h := hashToCurve(byte(i%2), i, input)
		require.False(t, isInfinity(h))
		hb, err := pointToCompressed(h)
		require.NoError(t, err)
		_, err = compressedToPoint(hb)
		require.NoError(t, err)
	}
}

func TestSelectPoint(t *testing.T) {
	t.Parallel()
	a, err := sampleScalar()
	require.NoError(t, err)
	b, err := sampleScalar()
	require.NoError(t, err)
	var p0, p1 btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(&a, &p0)
	btcec.ScalarBaseMultNonConst(&b, &p1)
	// Non-affine representatives (Z != 1) must be handled too.
	p0j := pointAdd(&p0, &p1)
	p1j := pointAdd(&p1, &p1)

	encode := func(p *btcec.JacobianPoint) []byte {
		var c btcec.JacobianPoint
		c.Set(p)
		enc, err := pointToCompressed(&c)
		require.NoError(t, err)
		return enc
	}
	want0, want1 := encode(p0j), encode(p1j)
	require.NotEqual(t, want0, want1)

	require.Equal(t, want0, encode(selectPoint(0, p0j, p1j)))
	require.Equal(t, want1, encode(selectPoint(1, p0j, p1j)))

	// Inputs are left unchanged.
	require.Equal(t, want0, encode(p0j))
	require.Equal(t, want1, encode(p1j))
}

func TestPointSubAndIsInfinity(t *testing.T) {
	t.Parallel()
	a, err := sampleScalar()
	require.NoError(t, err)
	b, err := sampleScalar()
	require.NoError(t, err)
	var sum btcec.ModNScalar
	sum.Add2(&a, &b)

	var aG, bG, sumG btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(&a, &aG)
	btcec.ScalarBaseMultNonConst(&b, &bG)
	btcec.ScalarBaseMultNonConst(&sum, &sumG)

	// (a+b)G − bG == aG.
	got, err := pointToCompressed(pointSub(&sumG, &bG))
	require.NoError(t, err)
	want, err := pointToCompressed(&aG)
	require.NoError(t, err)
	require.Equal(t, want, got)

	// P − P is the point at infinity; a finite point is not.
	require.True(t, isInfinity(pointSub(&aG, &aG)))
	require.False(t, isInfinity(&aG))
	var zero btcec.JacobianPoint
	require.True(t, isInfinity(&zero))
	_, err = pointToCompressed(pointSub(&aG, &aG))
	require.Error(t, err)
}

func TestBaseOTReceiverStateZero(t *testing.T) {
	t.Parallel()
	var nilState *BaseOTReceiverState
	require.NotPanics(t, func() { nilState.Zero() })

	st := &BaseOTReceiverState{Choices: []bool{true, true}, A: make([]btcec.ModNScalar, 2)}
	st.A[0].SetInt(5)
	st.A[1].SetInt(7)
	st.Zero()
	for k := range st.A {
		require.True(t, st.A[k].IsZero())
		require.False(t, st.Choices[k])
	}
	// Idempotent.
	require.NotPanics(t, func() { st.Zero() })
}

func TestScalarInverseCorrectness(t *testing.T) {
	for i := 0; i < 10; i++ {
		a, err := sampleScalar()
		require.NoError(t, err)
		aInv := scalarInverse(&a)
		var product btcec.ModNScalar
		product.Mul2(&a, &aInv)
		var one btcec.ModNScalar
		one.SetInt(1)
		require.True(t, product.Equals(&one), "a * a^(-1) must equal 1")
	}
}

func TestScalarInverseKnownValue(t *testing.T) {
	var two btcec.ModNScalar
	two.SetInt(2)
	inv := scalarInverse(&two)
	var product btcec.ModNScalar
	product.Mul2(&two, &inv)
	var one btcec.ModNScalar
	one.SetInt(1)
	require.True(t, product.Equals(&one))
}
