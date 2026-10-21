package dkls23

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"golang.org/x/crypto/sha3"
)

// --- One-message KOS15 OT Extension realizing FEOTE(Zq^{Ell+Rho}, Xi) ---
//
// DKLS23 (Functionality 5.1 / Section 5.1 / Section 8.1) requires an endemic
// OT-extension functionality in which a one-time setup of exactly LambdaC base
// OTs is followed by any number of extension batches, each tied to a fresh
// session id. The paper suggests SoftSpokenOT [Roy22] with the one-message
// Fiat-Shamir optimisation of §5.1, and notes that other OT extensions
// realizing FEOTE are acceptable. This file implements the actively secure
// OT extension of Keller, Orsini and Scholl (KOS15, "Actively Secure OT
// Extension with Optimal Overhead", Figure 7), i.e. the k = 1 instance of the
// SoftSpokenOT family, under the §5.1 modification:
//
//   - the consistency-check challenge (χ_1, …, χ_ℓ') is derived with the
//     Fiat-Shamir transform from the receiver's correction matrix U via a
//     non-programmable random oracle, so one batch is a single message from
//     the receiver to the sender; and
//   - because the adversary can grind the challenge, every occurrence of the
//     statistical parameter s is replaced by the computational parameter κ
//     (= LambdaC), so the padded batch length is ℓ' = Xi + 2*LambdaC = XiExt.
//
// Role mapping (fixed by the base OT):
//
//   - VOLE Bob is the OT-extension RECEIVER and the base-OT SENDER. He holds
//     the seed pairs (K^0_k, K^1_k) for k in [LambdaC].
//   - VOLE Alice is the OT-extension SENDER and the base-OT RECEIVER. She
//     holds Δ = sigma in {0,1}^LambdaC and the seeds K^{sigma_k}_k.
//
// Per batch with session id sid:
//
//	Bob:   x = beta || random pad (XiExt bits)
//	       t_k = PRF(K^0_k, sid);  u_k = t_k ⊕ PRF(K^1_k, sid) ⊕ x
//	       χ_j = RO(sid, u_1..u_LambdaC);  x̄ = Σ x_j χ_j;  t̄ = Σ t^j χ_j   (GF(2^128))
//	       gamma_j = H(x_j, j, sid, t^j) expanded to Ell+Rho field elements
//	Alice: q_k = PRF(K^{sigma_k}_k, sid) ⊕ sigma_k·u_k   (= t_k ⊕ sigma_k·x)
//	       q̄ = Σ q^j χ_j;  check q̄ == t̄ ⊕ x̄·Δ
//	       alpha0_j = H(0, j, sid, q^j);  alpha1_j = H(1, j, sid, q^j ⊕ Δ)
//
// The base seeds are reused across batches; keying the PRF by sid is what
// makes every batch fresh. Only the first Xi columns produce OT outputs; the
// 2*LambdaC pad columns exist solely to protect Bob's choice bits in the check.

// OTExtReceiverMsg is the single message from the OT-extension receiver (Bob)
// to the sender (Alice) for one batch.
type OTExtReceiverMsg struct {
	// U is the correction matrix: LambdaC rows of XiExt bits each.
	U [][XiExt / 8]byte
	// XBar is x̄ = Σ_j x_j · χ_j in GF(2^128).
	XBar [LambdaC / 8]byte
	// TBar is t̄ = Σ_j t^j · χ_j in GF(2^128).
	TBar [LambdaC / 8]byte
}

// otePRFSeedLen is the length of a base-OT seed (SHAKE256 output in ot.go).
const otePRFSeedLen = 32

// prg expands a base-OT seed to XiExt bits for the batch with session id sid:
// SHAKE256("ote-prg" || seed || sid). Seeds are fixed-length (32 bytes), so
// the concatenation is unambiguous.
func prg(seed, sid []byte) [XiExt / 8]byte {
	h := sha3.NewShake256()
	h.Write([]byte(domainOTEPRG))
	h.Write(seed)
	h.Write(sid)
	var out [XiExt / 8]byte
	h.Read(out[:])
	return out
}

// xorBitVec XORs two XiExt-bit vectors.
func xorBitVec(a, b [XiExt / 8]byte) [XiExt / 8]byte {
	var out [XiExt / 8]byte
	for i := range out {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// andBitVecMask ANDs every byte of v with mask (0x00 or 0xFF).
func andBitVecMask(v [XiExt / 8]byte, mask byte) [XiExt / 8]byte {
	var out [XiExt / 8]byte
	for i := range out {
		out[i] = v[i] & mask
	}
	return out
}

// boolsToBitVec packs beta into the first Xi bits of an XiExt-bit vector
// (LSB-first per byte) without branching on the bits. The pad bits are zero.
func boolsToBitVec(beta [Xi]bool) [XiExt / 8]byte {
	var out [XiExt / 8]byte
	for j, b := range beta {
		out[j/8] |= byte(condUint32(b)) << (uint(j) % 8)
	}
	return out
}

// getBitByte returns bit j (LSB-first) of v as 0 or 1.
func getBitByte(v [XiExt / 8]byte, j int) byte {
	return (v[j/8] >> (uint(j) % 8)) & 1
}

// getColumnLambdaC extracts column j of the LambdaC x XiExt matrix stored as
// rows[k] in {0,1}^XiExt, returning the LambdaC bits packed LSB-first. The
// extraction is branch-free in the (secret) matrix contents.
func getColumnLambdaC(rows [][XiExt / 8]byte, j int) gf128 {
	var out gf128
	for k := 0; k < LambdaC; k++ {
		out[k/8] |= getBitByte(rows[k], j) << (uint(k) % 8)
	}
	return out
}

// packSigma packs sigma in {0,1}^LambdaC into Δ (LSB-first per byte).
func packSigma(sigma []bool) gf128 {
	var out gf128
	for k, s := range sigma {
		out[k/8] |= byte(condUint32(s)) << (uint(k) % 8)
	}
	return out
}

// oteChallenge derives the KOS consistency-check challenge
// (χ_1, …, χ_XiExt) by reading sequential 16-byte GF(2^128) elements from
// SHAKE256("ote-kos" || sid || u_1 || … || u_LambdaC).
func oteChallenge(sid []byte, U [][XiExt / 8]byte) [XiExt]gf128 {
	h := sha3.NewShake256()
	h.Write([]byte(domainOTEKOS))
	h.Write(sid)
	for k := range U {
		h.Write(U[k][:])
	}
	var chi [XiExt]gf128
	for j := range chi {
		h.Read(chi[j][:])
	}
	return chi
}

// oteSeedHash computes SHAKE256("ote-seed" || choice_byte || j || col || sid) → 32 bytes.
// col is a fixed 16-byte column, so the trailing variable-length sid is
// unambiguous. The choice bit is written branchlessly.
func oteSeedHash(choice bool, j int, sid []byte, col gf128) []byte {
	h := sha3.NewShake256()
	h.Write([]byte(domainOTESeed))
	h.Write([]byte{byte(condUint32(choice))})
	var jbuf [8]byte
	binary.BigEndian.PutUint64(jbuf[:], uint64(j))
	h.Write(jbuf[:])
	h.Write(col[:])
	h.Write(sid)
	out := make([]byte, 32)
	h.Read(out)
	return out
}

// oteExpandHash computes SHAKE256("ote-expand" || choice_byte || j || i || seed) mod q → stored in 32 bytes.
// The choice bit is written branchlessly.
func oteExpandHash(choice bool, j, i int, seed []byte) [32]byte {
	h := sha3.NewShake256()
	h.Write([]byte(domainOTEExpand))
	h.Write([]byte{byte(condUint32(choice))})
	var jbuf [8]byte
	binary.BigEndian.PutUint64(jbuf[:], uint64(j))
	h.Write(jbuf[:])
	binary.BigEndian.PutUint64(jbuf[:], uint64(i))
	h.Write(jbuf[:])
	h.Write(seed)

	// The seed is secret, so the reduction mod q must be constant time:
	// ModNScalar.SetBytes reduces a 256-bit value in constant time. The
	// resulting bias toward small values is (2^256 - q) / 2^256 < 2^-127,
	// which is negligible.
	var raw [32]byte
	h.Read(raw[:])
	var v btcec.ModNScalar
	v.SetBytes(&raw)
	out := v.Bytes()
	v.Zero()
	for b := range raw {
		raw[b] = 0
	}
	return out
}

// oteExpandColumn derives the Ell+Rho field elements for OT index j from
// column col under choice bit choice.
func oteExpandColumn(choice bool, j int, sid []byte, col gf128) [Ell + Rho][32]byte {
	seed := oteSeedHash(choice, j, sid, col)
	var out [Ell + Rho][32]byte
	for i := 0; i < Ell+Rho; i++ {
		out[i] = oteExpandHash(choice, j, i, seed)
	}
	for i := range seed {
		seed[i] = 0
	}
	return out
}

// checkSeeds validates that seeds has exactly LambdaC entries of otePRFSeedLen bytes.
func checkSeeds(fn, name string, seeds [][]byte) error {
	if len(seeds) != LambdaC {
		return fmt.Errorf("dkls23 %s: %s must have %d entries, got %d", fn, name, LambdaC, len(seeds))
	}
	for k, s := range seeds {
		if len(s) != otePRFSeedLen {
			return fmt.Errorf("dkls23 %s: %s[%d] must be %d bytes, got %d", fn, name, k, otePRFSeedLen, len(s))
		}
	}
	return nil
}

// OTExtReceive runs the OT-extension receiver (VOLE Bob) for one batch with
// session id sid. Bob's base-OT sender seed pairs are (bobSeeds0[k], bobSeeds1[k])
// and his choice bits are beta. It returns the single message for Alice and
// Bob's OT outputs gamma, where gamma[j] equals alpha_{beta_j}[j] on Alice's
// side for every j in [Xi].
//
// sid must be unique per batch: reusing a sid with the same base seeds
// reproduces the same correlation, which the VOLE built on top of it does not
// tolerate (DKLS23 Functionality 5.1 requires sid to be fresh).
func OTExtReceive(bobSeeds0, bobSeeds1 [][]byte, beta [Xi]bool, sid []byte) (*OTExtReceiverMsg, [][Ell + Rho][32]byte, error) {
	const fn = "OTExtReceive"
	if err := checkSeeds(fn, "bobSeeds0", bobSeeds0); err != nil {
		return nil, nil, err
	}
	if err := checkSeeds(fn, "bobSeeds1", bobSeeds1); err != nil {
		return nil, nil, err
	}
	if len(sid) == 0 {
		return nil, nil, errors.New("dkls23 OTExtReceive: sid must be non-empty")
	}

	// x = beta || sacrificial random pad.
	x := boolsToBitVec(beta)
	if _, err := rand.Read(x[Xi/8:]); err != nil {
		return nil, nil, fmt.Errorf("dkls23 OTExtReceive: sampling pad: %w", err)
	}

	// T rows and corrections U.
	T := make([][XiExt / 8]byte, LambdaC)
	msg := &OTExtReceiverMsg{U: make([][XiExt / 8]byte, LambdaC)}
	for k := 0; k < LambdaC; k++ {
		T[k] = prg(bobSeeds0[k], sid)
		msg.U[k] = xorBitVec(xorBitVec(T[k], prg(bobSeeds1[k], sid)), x)
	}

	// Fiat-Shamir challenge and check values over all XiExt columns.
	chi := oteChallenge(sid, msg.U)
	var xBar, tBar gf128
	for j := 0; j < XiExt; j++ {
		xBar = gf128Xor(xBar, gf128MulBit(chi[j], getBitByte(x, j)))
		tBar = gf128Xor(tBar, gf128Mul(getColumnLambdaC(T, j), chi[j]))
	}
	msg.XBar = xBar
	msg.TBar = tBar

	// Outputs for the Xi useful columns only.
	gamma := make([][Ell + Rho][32]byte, Xi)
	for j := 0; j < Xi; j++ {
		gamma[j] = oteExpandColumn(beta[j], j, sid, getColumnLambdaC(T, j))
	}

	// Scrub the per-batch secrets.
	for k := range T {
		for i := range T[k] {
			T[k][i] = 0
		}
	}
	for i := range x {
		x[i] = 0
	}
	return msg, gamma, nil
}

// OTExtSend runs the OT-extension sender (VOLE Alice) for one batch with
// session id sid. Alice's base-OT receiver choice bits are sigma and her seeds
// are aliceSeeds[k] = K^{sigma_k}_k. It verifies the KOS15 consistency check
// on msg and returns Alice's OT output pairs (alpha0, alpha1), each of length
// Xi. If the check fails the returned error reports it and the caller should
// treat Bob as cheating.
//
// As for OTExtReceive, sid must be fresh per batch: Alice must not accept two
// batches under the same sid with the same base seeds.
func OTExtSend(aliceSeeds [][]byte, sigma []bool, sid []byte, msg *OTExtReceiverMsg) (alpha0, alpha1 [][Ell + Rho][32]byte, err error) {
	const fn = "OTExtSend"
	if err := checkSeeds(fn, "aliceSeeds", aliceSeeds); err != nil {
		return nil, nil, err
	}
	if len(sigma) != LambdaC {
		return nil, nil, fmt.Errorf("dkls23 OTExtSend: sigma must have %d entries, got %d", LambdaC, len(sigma))
	}
	if len(sid) == 0 {
		return nil, nil, errors.New("dkls23 OTExtSend: sid must be non-empty")
	}
	if msg == nil {
		return nil, nil, errors.New("dkls23 OTExtSend: nil receiver message")
	}
	if len(msg.U) != LambdaC {
		return nil, nil, fmt.Errorf("dkls23 OTExtSend: U must have %d rows, got %d", LambdaC, len(msg.U))
	}

	// Q rows: q_k = PRF(K^{sigma_k}_k, sid) XOR sigma_k * u_k, with sigma_k
	// applied as a byte mask rather than a branch.
	Q := make([][XiExt / 8]byte, LambdaC)
	for k := 0; k < LambdaC; k++ {
		mask := -byte(condUint32(sigma[k]))
		Q[k] = xorBitVec(prg(aliceSeeds[k], sid), andBitVecMask(msg.U[k], mask))
	}
	delta := packSigma(sigma)

	// Recompute the challenge and verify q̄ == t̄ XOR x̄·Δ.
	chi := oteChallenge(sid, msg.U)
	var qBar gf128
	for j := 0; j < XiExt; j++ {
		qBar = gf128Xor(qBar, gf128Mul(getColumnLambdaC(Q, j), chi[j]))
	}
	expected := gf128Xor(gf128(msg.TBar), gf128Mul(gf128(msg.XBar), delta))
	if subtle.ConstantTimeCompare(qBar[:], expected[:]) != 1 {
		return nil, nil, errors.New("dkls23 OTExtSend: KOS consistency check failed: receiver corrections are inconsistent")
	}

	// Outputs for the Xi useful columns.
	alpha0 = make([][Ell + Rho][32]byte, Xi)
	alpha1 = make([][Ell + Rho][32]byte, Xi)
	for j := 0; j < Xi; j++ {
		qj := getColumnLambdaC(Q, j)
		alpha0[j] = oteExpandColumn(false, j, sid, qj)
		alpha1[j] = oteExpandColumn(true, j, sid, gf128Xor(qj, delta))
	}

	// Scrub the per-batch secrets.
	for k := range Q {
		for i := range Q[k] {
			Q[k][i] = 0
		}
	}
	for i := range delta {
		delta[i] = 0
	}
	return alpha0, alpha1, nil
}

// --- JSON encoding ---

type otExtReceiverMsgJSON struct {
	U    []string `json:"u"`
	XBar string   `json:"x_bar"`
	TBar string   `json:"t_bar"`
}

// MarshalJSON encodes the message with hex-encoded rows and check values.
func (m *OTExtReceiverMsg) MarshalJSON() ([]byte, error) {
	rows := make([]string, len(m.U))
	for k := range m.U {
		rows[k] = bytesToHex(m.U[k][:])
	}
	return json.Marshal(otExtReceiverMsgJSON{
		U:    rows,
		XBar: bytesToHex(m.XBar[:]),
		TBar: bytesToHex(m.TBar[:]),
	})
}

// UnmarshalJSON decodes the message, strictly validating that U has LambdaC
// rows of XiExt/8 bytes and that XBar and TBar are LambdaC/8 bytes each.
func (m *OTExtReceiverMsg) UnmarshalJSON(data []byte) error {
	var j otExtReceiverMsgJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	if len(j.U) != LambdaC {
		return fmt.Errorf("dkls23 OTExtReceiverMsg: U must have %d rows, got %d", LambdaC, len(j.U))
	}
	U := make([][XiExt / 8]byte, LambdaC)
	for k, s := range j.U {
		b, err := hexToBytes(s)
		if err != nil {
			return fmt.Errorf("dkls23 OTExtReceiverMsg: U[%d]: %w", k, err)
		}
		if len(b) != XiExt/8 {
			return fmt.Errorf("dkls23 OTExtReceiverMsg: U[%d] must be %d bytes, got %d", k, XiExt/8, len(b))
		}
		copy(U[k][:], b)
	}
	xBar, err := hexToFixed16(j.XBar)
	if err != nil {
		return fmt.Errorf("dkls23 OTExtReceiverMsg: x_bar: %w", err)
	}
	tBar, err := hexToFixed16(j.TBar)
	if err != nil {
		return fmt.Errorf("dkls23 OTExtReceiverMsg: t_bar: %w", err)
	}
	m.U = U
	m.XBar = xBar
	m.TBar = tBar
	return nil
}
