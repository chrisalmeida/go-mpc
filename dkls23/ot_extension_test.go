package dkls23

import (
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The tests in this file are self-contained: apart from the base-OT functions
// in ot.go they rely only on helpers defined below.

// oteRandomBools returns n uniformly random booleans.
func oteRandomBools(t *testing.T, n int) []bool {
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

// oteRandomBeta returns a uniformly random OT-extension receiver input.
func oteRandomBeta(t *testing.T) [Xi]bool {
	t.Helper()
	var beta [Xi]bool
	copy(beta[:], oteRandomBools(t, Xi))
	return beta
}

// oteFixture holds a real base-OT setup between Bob (base-OT sender,
// OT-extension receiver) and Alice (base-OT receiver, OT-extension sender).
type oteFixture struct {
	bobSeeds0, bobSeeds1 [][]byte
	aliceSeeds           [][]byte
	sigma                []bool
	beta                 [Xi]bool
}

// newOTEFixtureWithSigma runs the Masny-Rindal base OT with Alice's choice
// bits fixed to sigma.
func newOTEFixtureWithSigma(t *testing.T, sigma []bool) *oteFixture {
	t.Helper()
	// Alice (base-OT receiver, choice bits sigma) speaks first.
	state, msg, err := BaseOTReceiverRound1(sigma)
	require.NoError(t, err)

	// Bob (base-OT sender) derives both seed pairs and replies.
	bobSeeds0, bobSeeds1, reply, err := BaseOTSenderRound2(msg)
	require.NoError(t, err)

	// Alice derives K^{sigma_k}_k; her key-agreement secrets are zeroized.
	aliceSeeds, err := BaseOTReceiverFinalize(state, reply)
	require.NoError(t, err)

	return &oteFixture{
		bobSeeds0:  bobSeeds0,
		bobSeeds1:  bobSeeds1,
		aliceSeeds: aliceSeeds,
		sigma:      sigma,
		beta:       oteRandomBeta(t),
	}
}

// newOTEFixture runs the base OT with random sigma and random beta.
func newOTEFixture(t *testing.T) *oteFixture {
	t.Helper()
	return newOTEFixtureWithSigma(t, oteRandomBools(t, LambdaC))
}

// assertOTECorrect checks gamma[j] == alpha_{beta_j}[j] for all j in [Xi], and
// that the unchosen message is different.
func assertOTECorrect(t *testing.T, beta [Xi]bool, alpha0, alpha1, gamma [][Ell + Rho][32]byte) {
	t.Helper()
	require.Len(t, alpha0, Xi)
	require.Len(t, alpha1, Xi)
	require.Len(t, gamma, Xi)
	for j := 0; j < Xi; j++ {
		for i := 0; i < Ell+Rho; i++ {
			if beta[j] {
				require.Equal(t, alpha1[j][i], gamma[j][i], "OTE mismatch at j=%d i=%d (beta=true)", j, i)
				require.NotEqual(t, alpha0[j][i], gamma[j][i], "alpha0 must differ at j=%d i=%d", j, i)
			} else {
				require.Equal(t, alpha0[j][i], gamma[j][i], "OTE mismatch at j=%d i=%d (beta=false)", j, i)
				require.NotEqual(t, alpha1[j][i], gamma[j][i], "alpha1 must differ at j=%d i=%d", j, i)
			}
		}
	}
}

// cloneOTEMsg deep-copies a receiver message so tests can tamper with it.
func cloneOTEMsg(m *OTExtReceiverMsg) *OTExtReceiverMsg {
	out := &OTExtReceiverMsg{
		U:    make([][XiExt / 8]byte, len(m.U)),
		XBar: m.XBar,
		TBar: m.TBar,
	}
	copy(out.U, m.U)
	return out
}

// oteJSONRoundTrip marshals m, unmarshals it into a fresh message, and checks
// that re-marshaling yields byte-identical JSON.
func oteJSONRoundTrip(t *testing.T, m *OTExtReceiverMsg) *OTExtReceiverMsg {
	t.Helper()
	b1, err := json.Marshal(m)
	require.NoError(t, err)
	require.NotEmpty(t, b1)

	var out OTExtReceiverMsg
	require.NoError(t, json.Unmarshal(b1, &out))

	b2, err := json.Marshal(&out)
	require.NoError(t, err)
	require.JSONEq(t, string(b1), string(b2), "OTExtReceiverMsg round-trip JSON mismatch")
	return &out
}

// maliciousOTExtReceive mirrors OTExtReceive, except that the receiver encodes
// the choice bit of column badCol inconsistently in row badRow (that row uses
// x XOR e_badCol). The Fiat-Shamir challenge is derived from the malformed U
// exactly as an adversary would, and x̄, t̄ are computed honestly from x and T.
// This is the attack on passive IKNP that the KOS15 consistency check exists
// to detect: Alice's q^badCol is shifted by sigma_badRow · e_badRow, so the
// check fails iff sigma_badRow = 1.
func maliciousOTExtReceive(t *testing.T, f *oteFixture, sid []byte, badRow, badCol int) *OTExtReceiverMsg {
	t.Helper()
	x := boolsToBitVec(f.beta)
	_, err := rand.Read(x[Xi/8:])
	require.NoError(t, err)

	T := make([][XiExt / 8]byte, LambdaC)
	msg := &OTExtReceiverMsg{U: make([][XiExt / 8]byte, LambdaC)}
	for k := 0; k < LambdaC; k++ {
		T[k] = prg(f.bobSeeds0[k], sid)
		msg.U[k] = xorBitVec(xorBitVec(T[k], prg(f.bobSeeds1[k], sid)), x)
	}
	msg.U[badRow][badCol/8] ^= 1 << (uint(badCol) % 8)

	chi := oteChallenge(sid, msg.U)
	for j := 0; j < XiExt; j++ {
		msg.XBar = gf128Xor(msg.XBar, gf128MulBit(chi[j], getBitByte(x, j)))
		msg.TBar = gf128Xor(msg.TBar, gf128Mul(getColumnLambdaC(T, j), chi[j]))
	}
	return msg
}

func TestOTExtensionCorrectness(t *testing.T) {
	t.Parallel()
	f := newOTEFixture(t)
	sid := []byte("ote-test-session-1")

	msg, gamma, err := OTExtReceive(f.bobSeeds0, f.bobSeeds1, f.beta, sid)
	require.NoError(t, err)
	require.Len(t, msg.U, LambdaC)
	require.Len(t, gamma, Xi)

	alpha0, alpha1, err := OTExtSend(f.aliceSeeds, f.sigma, sid, msg)
	require.NoError(t, err)

	assertOTECorrect(t, f.beta, alpha0, alpha1, gamma)
}

func TestOTExtensionAllZeroAndAllOneBeta(t *testing.T) {
	t.Parallel()
	f := newOTEFixture(t)

	var zero, one [Xi]bool
	for j := range one {
		one[j] = true
	}
	for n, beta := range [][Xi]bool{zero, one} {
		sid := []byte{byte(n), 'o', 't', 'e', '-', 'c', 'o', 'n', 's', 't'}
		msg, gamma, err := OTExtReceive(f.bobSeeds0, f.bobSeeds1, beta, sid)
		require.NoError(t, err)
		alpha0, alpha1, err := OTExtSend(f.aliceSeeds, f.sigma, sid, msg)
		require.NoError(t, err)
		assertOTECorrect(t, beta, alpha0, alpha1, gamma)
	}
}

func TestOTExtensionMultipleBatchesSameSeeds(t *testing.T) {
	t.Parallel()
	f := newOTEFixture(t)

	// The base seeds are a one-time setup; several batches with distinct sids
	// must each verify and each be correct, with independent beta per batch.
	for n := 0; n < 3; n++ {
		beta := oteRandomBeta(t)
		sid := []byte("ote-multi-batch-" + strings.Repeat("x", n+1))
		msg, gamma, err := OTExtReceive(f.bobSeeds0, f.bobSeeds1, beta, sid)
		require.NoError(t, err)
		alpha0, alpha1, err := OTExtSend(f.aliceSeeds, f.sigma, sid, msg)
		require.NoError(t, err)
		assertOTECorrect(t, beta, alpha0, alpha1, gamma)
	}
}

func TestOTExtensionTamperU(t *testing.T) {
	t.Parallel()
	f := newOTEFixture(t)
	sid := []byte("ote-tamper-u")

	msg, _, err := OTExtReceive(f.bobSeeds0, f.bobSeeds1, f.beta, sid)
	require.NoError(t, err)

	// Flip single bits spread across rows and columns (including the
	// sacrificial pad columns). Any change to U changes the Fiat-Shamir
	// challenge, so t̄ no longer matches and every flip must be detected,
	// whatever Alice's sigma is.
	positions := [][2]int{
		{0, 0}, {LambdaC - 1, XiExt - 1}, {17, Xi}, {64, Xi / 2}, {127, XiExt - 8}, {5, 400},
	}
	for _, p := range positions {
		k, bit := p[0], p[1]
		tampered := cloneOTEMsg(msg)
		tampered.U[k][bit/8] ^= 1 << (uint(bit) % 8)
		_, _, err := OTExtSend(f.aliceSeeds, f.sigma, sid, tampered)
		require.Error(t, err, "flipping U[%d] bit %d must fail", k, bit)
		require.Contains(t, err.Error(), "consistency check failed")
	}

	// Untampered still passes.
	_, _, err = OTExtSend(f.aliceSeeds, f.sigma, sid, msg)
	require.NoError(t, err)
}

func TestOTExtensionTamperXBarTBar(t *testing.T) {
	t.Parallel()
	f := newOTEFixture(t)
	sid := []byte("ote-tamper-bars")

	msg, _, err := OTExtReceive(f.bobSeeds0, f.bobSeeds1, f.beta, sid)
	require.NoError(t, err)

	for bit := 0; bit < LambdaC; bit += 7 {
		tampered := cloneOTEMsg(msg)
		tampered.XBar[bit/8] ^= 1 << (uint(bit) % 8)
		_, _, err := OTExtSend(f.aliceSeeds, f.sigma, sid, tampered)
		require.Error(t, err, "flipping XBar bit %d must fail", bit)
		require.Contains(t, err.Error(), "consistency check failed")

		tampered = cloneOTEMsg(msg)
		tampered.TBar[bit/8] ^= 1 << (uint(bit) % 8)
		_, _, err = OTExtSend(f.aliceSeeds, f.sigma, sid, tampered)
		require.Error(t, err, "flipping TBar bit %d must fail", bit)
		require.Contains(t, err.Error(), "consistency check failed")
	}
}

// TestOTExtensionTamperEveryXBarBit exhaustively flips every bit of XBar.
// Flipping x̄ by one bit changes the expected value by x^bit · Δ, which is
// non-zero for every Δ != 0 because GF(2^128) has no zero divisors, so every
// single-bit tamper must be caught.
func TestOTExtensionTamperEveryXBarBit(t *testing.T) {
	t.Parallel()
	sigma := oteRandomBools(t, LambdaC)
	sigma[0] = true // guarantee Δ != 0 so that x̄ participates in the check
	f := newOTEFixtureWithSigma(t, sigma)

	sid := []byte("ote-tamper-every-xbar")
	msg, _, err := OTExtReceive(f.bobSeeds0, f.bobSeeds1, f.beta, sid)
	require.NoError(t, err)

	for bit := 0; bit < LambdaC; bit++ {
		tampered := cloneOTEMsg(msg)
		tampered.XBar[bit/8] ^= 1 << (uint(bit) % 8)
		_, _, err := OTExtSend(f.aliceSeeds, f.sigma, sid, tampered)
		require.Error(t, err, "flipping XBar bit %d must fail", bit)
	}
}

// TestOTExtensionMaliciousReceiverInconsistentRow exercises the KOS15
// consistency check itself (rather than the Fiat-Shamir binding of U): a
// cheating receiver who encodes a choice bit inconsistently across rows, and
// who computes the challenge from the U he actually sends.
func TestOTExtensionMaliciousReceiverInconsistentRow(t *testing.T) {
	t.Parallel()
	// sigma_k = 1 for odd k, 0 for even k, so both cases are available.
	sigma := make([]bool, LambdaC)
	for k := range sigma {
		sigma[k] = k%2 == 1
	}
	f := newOTEFixtureWithSigma(t, sigma)
	sid := []byte("ote-malicious-receiver")

	// Rows with sigma_k = 1: Alice folds u_k into q_k, so the deviation in
	// column c shifts q̄ by χ_c · e_k != 0 and the check must fail, whether c
	// is a useful column or a pad column.
	for _, p := range [][2]int{{1, 0}, {LambdaC - 1, Xi - 1}, {63, Xi + 5}, {3, XiExt - 1}} {
		msg := maliciousOTExtReceive(t, f, sid, p[0], p[1])
		_, _, err := OTExtSend(f.aliceSeeds, f.sigma, sid, msg)
		require.Error(t, err, "inconsistent row %d (sigma=1), column %d must fail", p[0], p[1])
		require.Contains(t, err.Error(), "consistency check failed")
	}

	// Rows with sigma_k = 0: Alice never reads u_k, so the deviation is
	// invisible and the check passes. This is the inherent selective-failure
	// behaviour of KOS15: each such gamble tells the receiver one bit of Δ and
	// is caught with probability 1/2, which the security analysis accounts
	// for. The check must not be stricter than the protocol specifies.
	for _, p := range [][2]int{{0, 0}, {LambdaC - 2, Xi - 1}, {64, XiExt - 1}} {
		msg := maliciousOTExtReceive(t, f, sid, p[0], p[1])
		_, _, err := OTExtSend(f.aliceSeeds, f.sigma, sid, msg)
		require.NoError(t, err, "inconsistent row %d (sigma=0), column %d is undetectable", p[0], p[1])
	}
}

func TestOTExtensionWrongSID(t *testing.T) {
	t.Parallel()
	f := newOTEFixture(t)

	msg, _, err := OTExtReceive(f.bobSeeds0, f.bobSeeds1, f.beta, []byte("sid-A"))
	require.NoError(t, err)

	// Alice using a different sid derives different PRF rows and challenge:
	// the check must fail.
	_, _, err = OTExtSend(f.aliceSeeds, f.sigma, []byte("sid-B"), msg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "consistency check failed")
}

func TestOTExtensionWrongSeeds(t *testing.T) {
	t.Parallel()
	f := newOTEFixture(t)
	g := newOTEFixture(t)
	sid := []byte("ote-wrong-seeds")

	msg, _, err := OTExtReceive(f.bobSeeds0, f.bobSeeds1, f.beta, sid)
	require.NoError(t, err)

	// Alice with seeds from an unrelated base OT must reject.
	_, _, err = OTExtSend(g.aliceSeeds, g.sigma, sid, msg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "consistency check failed")
}

func TestOTExtensionDifferentSIDDifferentOutputs(t *testing.T) {
	t.Parallel()
	f := newOTEFixture(t)

	msgA, gammaA, err := OTExtReceive(f.bobSeeds0, f.bobSeeds1, f.beta, []byte("sid-A"))
	require.NoError(t, err)
	msgB, gammaB, err := OTExtReceive(f.bobSeeds0, f.bobSeeds1, f.beta, []byte("sid-B"))
	require.NoError(t, err)

	// Same seeds and beta, different sid: every U row differs and outputs differ.
	for k := 0; k < LambdaC; k++ {
		require.NotEqual(t, msgA.U[k], msgB.U[k], "U row %d must differ across sids", k)
	}
	require.NotEqual(t, msgA.TBar, msgB.TBar)
	for j := 0; j < Xi; j++ {
		require.NotEqual(t, gammaA[j], gammaB[j], "gamma[%d] must differ across sids", j)
	}

	alpha0A, alpha1A, err := OTExtSend(f.aliceSeeds, f.sigma, []byte("sid-A"), msgA)
	require.NoError(t, err)
	alpha0B, alpha1B, err := OTExtSend(f.aliceSeeds, f.sigma, []byte("sid-B"), msgB)
	require.NoError(t, err)
	for j := 0; j < Xi; j++ {
		require.NotEqual(t, alpha0A[j], alpha0B[j], "alpha0[%d] must differ across sids", j)
		require.NotEqual(t, alpha1A[j], alpha1B[j], "alpha1[%d] must differ across sids", j)
	}
	assertOTECorrect(t, f.beta, alpha0A, alpha1A, gammaA)
	assertOTECorrect(t, f.beta, alpha0B, alpha1B, gammaB)
}

// TestOTExtensionSameSIDDeterministic pins down exactly which parts of a batch
// are a deterministic function of (seeds, sid, beta) and which are not, when a
// sid is (incorrectly) reused with the same base seeds.
func TestOTExtensionSameSIDDeterministic(t *testing.T) {
	t.Parallel()
	f := newOTEFixture(t)
	sid := []byte("sid-deterministic")

	msg1, gamma1, err := OTExtReceive(f.bobSeeds0, f.bobSeeds1, f.beta, sid)
	require.NoError(t, err)
	msg2, gamma2, err := OTExtReceive(f.bobSeeds0, f.bobSeeds1, f.beta, sid)
	require.NoError(t, err)

	// T = PRF(K^0, sid) and PRF(K^1, sid) depend only on (seeds, sid), and the
	// first Xi bits of x are beta, so Bob's outputs and the useful prefix of
	// every U row are reproduced exactly. This is precisely why a sid must
	// never be reused: the OT correlation would be reproduced too.
	require.Equal(t, gamma1, gamma2, "gamma must be deterministic in (seeds, sid, beta)")
	for k := 0; k < LambdaC; k++ {
		require.Equal(t, msg1.U[k][:Xi/8], msg2.U[k][:Xi/8], "useful bits of U[%d] must match", k)
	}

	// The 2*LambdaC pad bits of x are sampled fresh on every call, so each U
	// row differs from the first call by the same non-zero delta
	// (pad1 XOR pad2) confined to the pad region.
	diff := xorBitVec(msg1.U[0], msg2.U[0])
	require.NotEqual(t, [XiExt / 8]byte{}, diff, "pad must be fresh on every call")
	for k := 1; k < LambdaC; k++ {
		require.Equal(t, diff, xorBitVec(msg1.U[k], msg2.U[k]), "U[%d] must differ by the same pad delta", k)
	}

	// Because U changed, the Fiat-Shamir challenge χ = RO(sid, U) changed, so
	// x̄ = Σ x_j·χ_j and t̄ = Σ t^j·χ_j are not reproducible even though T is.
	require.NotEqual(t, msg1.XBar, msg2.XBar, "x̄ must change with the pad and the challenge")
	require.NotEqual(t, msg1.TBar, msg2.TBar, "t̄ must change with the challenge")

	// Alice's outputs are deterministic given the same message.
	a0, a1, err := OTExtSend(f.aliceSeeds, f.sigma, sid, msg1)
	require.NoError(t, err)
	b0, b1, err := OTExtSend(f.aliceSeeds, f.sigma, sid, msg1)
	require.NoError(t, err)
	require.Equal(t, a0, b0)
	require.Equal(t, a1, b1)

	// Both messages verify and yield the same alpha values: the useful columns
	// of Q = PRF(K^sigma, sid) XOR sigma·U do not involve the pad.
	c0, c1, err := OTExtSend(f.aliceSeeds, f.sigma, sid, msg2)
	require.NoError(t, err)
	require.Equal(t, a0, c0)
	require.Equal(t, a1, c1)
	assertOTECorrect(t, f.beta, a0, a1, gamma1)
}

func TestOTExtReceiveInputErrors(t *testing.T) {
	t.Parallel()
	f := newOTEFixture(t)
	sid := []byte("sid")

	_, _, err := OTExtReceive(f.bobSeeds0[:LambdaC-1], f.bobSeeds1, f.beta, sid)
	require.Error(t, err)
	require.Contains(t, err.Error(), "dkls23 OTExtReceive: bobSeeds0")

	_, _, err = OTExtReceive(f.bobSeeds0, f.bobSeeds1[:LambdaC-1], f.beta, sid)
	require.Error(t, err)
	require.Contains(t, err.Error(), "dkls23 OTExtReceive: bobSeeds1")

	short := make([][]byte, LambdaC)
	copy(short, f.bobSeeds0)
	short[3] = []byte{1, 2, 3}
	_, _, err = OTExtReceive(short, f.bobSeeds1, f.beta, sid)
	require.Error(t, err)
	require.Contains(t, err.Error(), "bobSeeds0[3]")

	_, _, err = OTExtReceive(f.bobSeeds0, f.bobSeeds1, f.beta, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "sid")

	_, _, err = OTExtReceive(nil, nil, f.beta, sid)
	require.Error(t, err)
}

func TestOTExtSendInputErrors(t *testing.T) {
	t.Parallel()
	f := newOTEFixture(t)
	sid := []byte("sid")
	msg, _, err := OTExtReceive(f.bobSeeds0, f.bobSeeds1, f.beta, sid)
	require.NoError(t, err)

	_, _, err = OTExtSend(f.aliceSeeds[:LambdaC-1], f.sigma, sid, msg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "dkls23 OTExtSend: aliceSeeds")

	short := make([][]byte, LambdaC)
	copy(short, f.aliceSeeds)
	short[9] = []byte{}
	_, _, err = OTExtSend(short, f.sigma, sid, msg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "aliceSeeds[9]")

	_, _, err = OTExtSend(f.aliceSeeds, f.sigma[:LambdaC-1], sid, msg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "sigma")

	_, _, err = OTExtSend(f.aliceSeeds, f.sigma, nil, msg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "sid")

	_, _, err = OTExtSend(f.aliceSeeds, f.sigma, sid, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "nil")

	bad := cloneOTEMsg(msg)
	bad.U = bad.U[:LambdaC-1]
	_, _, err = OTExtSend(f.aliceSeeds, f.sigma, sid, bad)
	require.Error(t, err)
	require.Contains(t, err.Error(), "U must have")

	bad = cloneOTEMsg(msg)
	bad.U = append(bad.U, [XiExt / 8]byte{})
	_, _, err = OTExtSend(f.aliceSeeds, f.sigma, sid, bad)
	require.Error(t, err)
	require.Contains(t, err.Error(), "U must have")
}

func TestOTExtReceiverMsgJSONRoundTrip(t *testing.T) {
	t.Parallel()
	m := &OTExtReceiverMsg{U: make([][XiExt / 8]byte, LambdaC)}
	for k := range m.U {
		_, err := rand.Read(m.U[k][:])
		require.NoError(t, err)
	}
	_, err := rand.Read(m.XBar[:])
	require.NoError(t, err)
	_, err = rand.Read(m.TBar[:])
	require.NoError(t, err)

	got := oteJSONRoundTrip(t, m)
	require.Equal(t, m.U, got.U)
	require.Equal(t, m.XBar, got.XBar)
	require.Equal(t, m.TBar, got.TBar)

	// The wire format uses exactly the field names "u", "x_bar" and "t_bar",
	// with hex-encoded rows of XiExt/8 bytes and 16-byte check values.
	raw, err := json.Marshal(m)
	require.NoError(t, err)
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &fields))
	require.Len(t, fields, 3)
	require.Contains(t, fields, "u")
	require.Contains(t, fields, "x_bar")
	require.Contains(t, fields, "t_bar")

	var rows []string
	require.NoError(t, json.Unmarshal(fields["u"], &rows))
	require.Len(t, rows, LambdaC)
	require.Equal(t, bytesToHex(m.U[0][:]), rows[0])
	var xBar, tBar string
	require.NoError(t, json.Unmarshal(fields["x_bar"], &xBar))
	require.NoError(t, json.Unmarshal(fields["t_bar"], &tBar))
	require.Equal(t, bytesToHex(m.XBar[:]), xBar)
	require.Equal(t, bytesToHex(m.TBar[:]), tBar)
}

func TestOTExtReceiverMsgJSONRoundTripRealBatch(t *testing.T) {
	t.Parallel()
	f := newOTEFixture(t)
	sid := []byte("ote-json-real")
	msg, gamma, err := OTExtReceive(f.bobSeeds0, f.bobSeeds1, f.beta, sid)
	require.NoError(t, err)

	got := oteJSONRoundTrip(t, msg)
	alpha0, alpha1, err := OTExtSend(f.aliceSeeds, f.sigma, sid, got)
	require.NoError(t, err)
	assertOTECorrect(t, f.beta, alpha0, alpha1, gamma)
}

func TestOTExtReceiverMsgJSONErrors(t *testing.T) {
	t.Parallel()
	goodRow := strings.Repeat("ab", XiExt/8)
	good16 := strings.Repeat("cd", LambdaC/8)
	rows := func(n int, row string) string {
		parts := make([]string, n)
		for i := range parts {
			parts[i] = `"` + row + `"`
		}
		return "[" + strings.Join(parts, ",") + "]"
	}
	cases := []struct {
		name    string
		json    string
		wantErr string
	}{
		{"not json", `{`, ""},
		{"wrong type for u", `{"u":"` + goodRow + `","x_bar":"` + good16 + `","t_bar":"` + good16 + `"}`, ""},
		{"too few rows", `{"u":` + rows(LambdaC-1, goodRow) + `,"x_bar":"` + good16 + `","t_bar":"` + good16 + `"}`, "U must have"},
		{"too many rows", `{"u":` + rows(LambdaC+1, goodRow) + `,"x_bar":"` + good16 + `","t_bar":"` + good16 + `"}`, "U must have"},
		{"missing u", `{"x_bar":"` + good16 + `","t_bar":"` + good16 + `"}`, "U must have"},
		{"bad row hex", `{"u":` + rows(LambdaC, "zz") + `,"x_bar":"` + good16 + `","t_bar":"` + good16 + `"}`, "U[0]"},
		{"short row", `{"u":` + rows(LambdaC, "abcd") + `,"x_bar":"` + good16 + `","t_bar":"` + good16 + `"}`, "must be 84 bytes"},
		{"long row", `{"u":` + rows(LambdaC, goodRow+"ab") + `,"x_bar":"` + good16 + `","t_bar":"` + good16 + `"}`, "must be 84 bytes"},
		{"bad x_bar hex", `{"u":` + rows(LambdaC, goodRow) + `,"x_bar":"zz","t_bar":"` + good16 + `"}`, "x_bar"},
		{"short x_bar", `{"u":` + rows(LambdaC, goodRow) + `,"x_bar":"abcd","t_bar":"` + good16 + `"}`, "x_bar"},
		{"missing x_bar", `{"u":` + rows(LambdaC, goodRow) + `,"t_bar":"` + good16 + `"}`, "x_bar"},
		{"bad t_bar hex", `{"u":` + rows(LambdaC, goodRow) + `,"x_bar":"` + good16 + `","t_bar":"zz"}`, "t_bar"},
		{"long t_bar", `{"u":` + rows(LambdaC, goodRow) + `,"x_bar":"` + good16 + `","t_bar":"` + good16 + `00"}`, "t_bar"},
		{"missing t_bar", `{"u":` + rows(LambdaC, goodRow) + `,"x_bar":"` + good16 + `"}`, "t_bar"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v OTExtReceiverMsg
			err := json.Unmarshal([]byte(tc.json), &v)
			require.Error(t, err)
			if tc.wantErr != "" {
				require.Contains(t, err.Error(), tc.wantErr)
			}
			// A failed unmarshal must not leave partial state behind.
			require.Nil(t, v.U)
			require.Equal(t, [LambdaC / 8]byte{}, v.XBar)
			require.Equal(t, [LambdaC / 8]byte{}, v.TBar)
		})
	}

	// The well-formed version of the same shape decodes.
	var v OTExtReceiverMsg
	err := json.Unmarshal([]byte(`{"u":`+rows(LambdaC, goodRow)+`,"x_bar":"`+good16+`","t_bar":"`+good16+`"}`), &v)
	require.NoError(t, err)
	require.Len(t, v.U, LambdaC)
}

// TestOTExtensionBitPacking checks the bit-vector helpers that carry beta,
// sigma and the matrix columns: packing order, pad handling, column
// extraction, and the XOR/AND primitives.
func TestOTExtensionBitPacking(t *testing.T) {
	t.Parallel()
	// boolsToBitVec packs beta into the first Xi bits with a zero pad.
	var beta [Xi]bool
	beta[0], beta[7], beta[8], beta[Xi-1] = true, true, true, true
	v := boolsToBitVec(beta)
	require.Equal(t, byte(0x81), v[0])
	require.Equal(t, byte(0x01), v[1])
	require.Equal(t, byte(0x80), v[Xi/8-1])
	for i := Xi / 8; i < XiExt/8; i++ {
		require.Equal(t, byte(0), v[i], "pad byte %d must be zero", i)
	}
	for j := 0; j < XiExt; j++ {
		want := byte(0)
		if j < Xi && beta[j] {
			want = 1
		}
		require.Equal(t, want, getBitByte(v, j))
	}

	// packSigma packs LSB-first per byte.
	sigma := make([]bool, LambdaC)
	sigma[1], sigma[127] = true, true
	d := packSigma(sigma)
	require.Equal(t, byte(0x02), d[0])
	require.Equal(t, byte(0x80), d[15])

	// getColumnLambdaC: row k has bit j set iff k == j%LambdaC.
	rows := make([][XiExt / 8]byte, LambdaC)
	for j := 0; j < XiExt; j++ {
		k := j % LambdaC
		rows[k][j/8] |= 1 << (uint(j) % 8)
	}
	for j := 0; j < XiExt; j++ {
		col := getColumnLambdaC(rows, j)
		var want gf128
		k := j % LambdaC
		want[k/8] = 1 << (uint(k) % 8)
		require.Equal(t, want, col, "column %d", j)
	}

	// xorBitVec and andBitVecMask.
	var full, other [XiExt / 8]byte
	for i := range full {
		full[i] = byte(i)
		other[i] = 0xFF
	}
	require.Equal(t, full, andBitVecMask(full, 0xFF))
	require.Equal(t, [XiExt / 8]byte{}, andBitVecMask(full, 0x00))
	require.Equal(t, [XiExt / 8]byte{}, xorBitVec(full, full))
	x := xorBitVec(full, other)
	for i := range x {
		require.Equal(t, byte(i)^0xFF, x[i])
	}
}

// TestOTExtensionPRGAndChallengeKeying checks that the row PRG is keyed by
// both the base seed and the session id, and that the Fiat-Shamir challenge
// is deterministic in (sid, U) and sensitive to every bit of either.
func TestOTExtensionPRGAndChallengeKeying(t *testing.T) {
	t.Parallel()
	// prg is keyed by both seed and sid.
	seed := make([]byte, 32)
	seed2 := make([]byte, 32)
	seed2[0] = 1
	require.NotEqual(t, prg(seed, []byte("a")), prg(seed, []byte("b")))
	require.NotEqual(t, prg(seed, []byte("a")), prg(seed2, []byte("a")))
	require.Equal(t, prg(seed, []byte("a")), prg(seed, []byte("a")))

	// The challenge depends on sid and on every bit of U, and is deterministic.
	U := make([][XiExt / 8]byte, LambdaC)
	c1 := oteChallenge([]byte("a"), U)
	require.Equal(t, c1, oteChallenge([]byte("a"), U))
	c2 := oteChallenge([]byte("b"), U)
	require.NotEqual(t, c1, c2)
	U[LambdaC-1][XiExt/8-1] ^= 0x80
	c3 := oteChallenge([]byte("a"), U)
	require.NotEqual(t, c1, c3)
}

// TestOTExtensionSeedHashDomainSeparation checks that the per-column OT
// output seed is separated by choice bit, column index, column value and
// session id.
func TestOTExtensionSeedHashDomainSeparation(t *testing.T) {
	t.Parallel()
	var col gf128
	base := oteSeedHash(false, 0, []byte("s"), col)
	require.Len(t, base, 32)
	require.NotEqual(t, base, oteSeedHash(true, 0, []byte("s"), col))
	require.NotEqual(t, base, oteSeedHash(false, 1, []byte("s"), col))
	require.NotEqual(t, base, oteSeedHash(false, 0, []byte("t"), col))
	col[0] = 1
	require.NotEqual(t, base, oteSeedHash(false, 0, []byte("s"), col))
}
