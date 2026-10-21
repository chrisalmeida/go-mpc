package dkls23

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"golang.org/x/crypto/sha3"
)

// --- Masny-Rindal endemic base OT (MR19) over secp256k1 ---
//
// DKLS23 §8.1 specifies that the LambdaC base OTs consumed by the OT
// extension are "supplied by the two-round UC-secure endemic OT protocol of
// Masny and Rindal [MR19]", instantiated "from the decisional Diffie-Hellman
// assumption over the same group G in which signatures are to be computed".
// This file implements the 1-out-of-2 case of MR19 Figure 8 with the
// Diffie-Hellman uniform key agreement of MR19 Appendix D.1 over secp256k1
// (group operation = point addition), with the OT output strings derived from
// the agreed keys through the random oracle as permitted by MR19 Remark D.4.
//
// Role mapping (fixed by the OT extension, see ot_extension.go):
//
//   - VOLE Bob   = OT-extension RECEIVER = base-OT SENDER.   He ends up with
//     the seed pairs (K^0_k, K^1_k) for k in [LambdaC].
//   - VOLE Alice = OT-extension SENDER   = base-OT RECEIVER with choice bits
//     sigma. She ends up with K^{sigma_k}_k for k in [LambdaC].
//
// One instance k, with H_0, H_1 : G → G random oracles realized by hashToCurve:
//
//	Receiver (choice bit c):  r_{1-c} ← G uniformly;  a ← Zq;  m_A = a·G;
//	                          r_c = m_A − H_c(r_{1-c});  send (r_0, r_1).
//	Sender:                   for j in {0,1}:  m_{A,j} = r_j + H_j(r_{1-j});
//	                          b_j ← Zq;  m_{B,j} = b_j·G;  s_{B,j} = b_j·m_{A,j};
//	                          send (m_{B,0}, m_{B,1}).
//	Receiver:                 s_{A,c} = a·m_{B,c}   (= a·b_c·G = s_{B,c}).
//	OT outputs:               K^j_k = SHAKE256(domainBaseOT || k || compressed(s_j)).
//
// Correctness: m_{A,c} = r_c + H_c(r_{1-c}) = m_A, so s_{B,c} = b_c·a·G = s_{A,c}.
// Sender security: m_{A,1-c} = r_{1-c} + H_{1-c}(r_c) has a discrete logarithm
// unknown to the receiver because H_{1-c}(r_c) is a random-oracle output, so
// K^{1-c}_k is hidden under DDH. Receiver security: (r_0, r_1) are both
// uniform in G, independent of c (endemic security, MR19 Theorem 4.1). Each
// party performs three scalar multiplications per instance on average and
// sends two group elements per instance, matching the cost stated in §8.1.
//
// Constant time: the receiver's choice bits are secret. Both H_0(r_{1-c}) and
// H_1(r_{1-c}) are computed and H_c is selected with a constant-time copy;
// (r_0, r_1) are placed with constant-time copies; m_{B,c} is selected with a
// constant-time copy. No code path branches on a choice bit. The inputs to
// H_j are public wire messages, so the variable number of trials inside
// hashToCurve leaks nothing.

// compressedPointLen is the byte length of a compressed secp256k1 point.
const compressedPointLen = btcec.PubKeyBytesLenCompressed

// compressedEvenPrefix is the SEC1 prefix byte of a compressed point with an
// even y-coordinate.
const compressedEvenPrefix = 0x02

// BaseOTReceiverMsg is the first base-OT message, sent by the base-OT
// receiver (VOLE Alice) to the base-OT sender (VOLE Bob). It carries the pair
// (r_0, r_1) of every OT instance (MR19 Figure 8, receiver message).
type BaseOTReceiverMsg struct {
	// R0 holds r_0 of each instance as a 33-byte compressed point.
	R0 [][]byte `json:"r0"`
	// R1 holds r_1 of each instance as a 33-byte compressed point.
	R1 [][]byte `json:"r1"`
}

// BaseOTSenderMsg is the second base-OT message, sent by the base-OT sender
// (VOLE Bob) to the base-OT receiver (VOLE Alice). It carries the pair
// (m_{B,0}, m_{B,1}) of every OT instance (MR19 Figure 8, sender message).
type BaseOTSenderMsg struct {
	// M0 holds m_{B,0} of each instance as a 33-byte compressed point.
	M0 [][]byte `json:"m0"`
	// M1 holds m_{B,1} of each instance as a 33-byte compressed point.
	M1 [][]byte `json:"m1"`
}

// BaseOTReceiverState is the base-OT receiver's private state between
// BaseOTReceiverRound1 and BaseOTReceiverFinalize. It must never leave the
// receiver's process: it contains the secret choice bits and the ephemeral
// Diffie-Hellman scalars. BaseOTReceiverFinalize zeroizes A; call Zero to
// erase everything (for example after an abort).
type BaseOTReceiverState struct {
	// Choices holds the receiver's secret choice bits c_k (a private copy of
	// the slice passed to BaseOTReceiverRound1).
	Choices []bool
	// A holds the ephemeral scalars a_k with m_{A,k} = a_k·G.
	A []btcec.ModNScalar
}

// Zero erases the receiver's secrets. It is safe to call on a nil state and
// more than once.
func (s *BaseOTReceiverState) Zero() {
	if s == nil {
		return
	}
	for k := range s.A {
		s.A[k].Zero()
	}
	for k := range s.Choices {
		s.Choices[k] = false
	}
}

// shake256Seed computes SHAKE256(domainBaseOT || k_bytes || point_compressed) → 32 bytes.
// It derives the OT output string K^j_k from an agreed Diffie-Hellman key
// (MR19 Remark D.4).
func shake256Seed(k int, pointCompressed []byte) []byte {
	h := sha3.NewShake256()
	h.Write([]byte(domainBaseOT))
	var kbuf [8]byte
	binary.BigEndian.PutUint64(kbuf[:], uint64(k))
	h.Write(kbuf[:])
	h.Write(pointCompressed)
	out := make([]byte, 32)
	h.Read(out)
	return out
}

// sampleScalar samples a uniformly random scalar in [1, q-1].
func sampleScalar() (btcec.ModNScalar, error) {
	for {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return btcec.ModNScalar{}, err
		}
		var s btcec.ModNScalar
		s.SetByteSlice(b)
		if !s.IsZero() {
			return s, nil
		}
	}
}

// hashToCurve realizes the random oracles H_j : G → G of MR19 Figure 8 for OT
// instance k. The XOF SHAKE256(domainBaseOTHash || j || k || input) is read as
// successive 32-byte candidate x-coordinates, and the first candidate that
// lies on secp256k1 is returned as the point with the even y-coordinate.
// Every candidate succeeds with probability about 1/2, so two trials are
// expected. Nobody knows the discrete logarithm of the output, which is what
// the sender's security relies on.
//
// Keying the oracle by the instance index k in addition to j is a
// domain-separation refinement of the paper's per-j oracles: the LambdaC
// instances of one setup use independent oracles instead of sharing H_0 and
// H_1. input is the 33-byte compressed encoding of the other r-value, which
// is public (it is sent on the wire), so the variable trial count is not a
// side channel.
func hashToCurve(j byte, k int, input []byte) *curvePoint {
	h := sha3.NewShake256()
	h.Write([]byte(domainBaseOTHash))
	h.Write([]byte{j})
	var kbuf [8]byte
	binary.BigEndian.PutUint64(kbuf[:], uint64(k))
	h.Write(kbuf[:])
	h.Write(input)

	var enc [compressedPointLen]byte
	enc[0] = compressedEvenPrefix
	for {
		h.Read(enc[1:])
		if p, err := compressedToPoint(enc[:]); err == nil {
			return p
		}
	}
}

// BaseOTReceiverRound1 runs the base-OT receiver's round (MR19 Figure 8) for
// len(choices) OT instances. For each instance k with choice bit c = choices[k]
// it samples r_{1-c} ← G and a_k ← Zq, sets r_c = a_k·G − H_c(r_{1-c}), and
// places (r_0, r_1) in the message. The returned state holds a_k and a private
// copy of the choice bits; pass it to BaseOTReceiverFinalize once the sender's
// reply arrives, or call its Zero method on abort.
//
// In the DKLS23 role mapping VOLE Alice calls this with choices = sigma.
func BaseOTReceiverRound1(choices []bool) (*BaseOTReceiverState, *BaseOTReceiverMsg, error) {
	n := len(choices)
	if n == 0 {
		return nil, nil, errors.New("dkls23 BaseOTReceiverRound1: choices must be non-empty")
	}
	state := &BaseOTReceiverState{
		Choices: make([]bool, n),
		A:       make([]btcec.ModNScalar, n),
	}
	copy(state.Choices, choices)
	msg := &BaseOTReceiverMsg{
		R0: make([][]byte, n),
		R1: make([][]byte, n),
	}

	for k := 0; k < n; k++ {
		// r_{1-c} ← G uniformly: a fresh scalar times G. The scalar itself is
		// not needed by the protocol and is erased immediately.
		rho, err := sampleScalar()
		if err != nil {
			state.Zero()
			return nil, nil, fmt.Errorf("dkls23 BaseOTReceiverRound1: sampling r at instance %d: %w", k, err)
		}
		rOther, err := scalarMulGCompressed(&rho)
		rho.Zero()
		if err != nil {
			state.Zero()
			return nil, nil, fmt.Errorf("dkls23 BaseOTReceiverRound1: instance %d: %w", k, err)
		}

		// a ← Zq;  m_A = a·G.
		state.A[k], err = sampleScalar()
		if err != nil {
			state.Zero()
			return nil, nil, fmt.Errorf("dkls23 BaseOTReceiverRound1: sampling a at instance %d: %w", k, err)
		}
		mA := scalarMulG(&state.A[k])

		// Compute both H_0(r_{1-c}) and H_1(r_{1-c}) on the public value
		// r_{1-c} and select H_c with a constant-time copy.
		c := int(condUint32(state.Choices[k]))
		h0 := hashToCurve(0, k, rOther)
		h1 := hashToCurve(1, k, rOther)
		hc, err := selectPoint(c, h0, h1)
		if err != nil {
			state.Zero()
			return nil, nil, fmt.Errorf("dkls23 BaseOTReceiverRound1: select point: %w", err)
		}

		// r_c = m_A − H_c(r_{1-c}).
		rcBytes, err := pointToCompressed(pointSub(mA, hc))
		if err != nil {
			// Only reachable if a·G == H_c(r_{1-c}), probability 1/q.
			state.Zero()
			return nil, nil, fmt.Errorf("dkls23 BaseOTReceiverRound1: instance %d: %w", k, err)
		}

		// Place (r_0, r_1) = c == 0 ? (r_c, r_{1-c}) : (r_{1-c}, r_c) with
		// constant-time copies.
		r0 := make([]byte, compressedPointLen)
		r1 := make([]byte, compressedPointLen)
		copy(r0, rcBytes)
		subtle.ConstantTimeCopy(c, r0, rOther)
		copy(r1, rOther)
		subtle.ConstantTimeCopy(c, r1, rcBytes)
		msg.R0[k] = r0
		msg.R1[k] = r1
	}
	return state, msg, nil
}

// BaseOTSenderRound2 runs the base-OT sender's round (MR19 Figure 8). For each
// instance k and each j in {0,1} it computes m_{A,j} = r_j + H_j(r_{1-j}),
// samples b_j ← Zq, replies with m_{B,j} = b_j·G, and derives the OT output
// string K^j_k from the agreed key s_{B,j} = b_j·m_{A,j}. seeds0[k] and
// seeds1[k] are the 32-byte strings K^0_k and K^1_k; the receiver learns
// exactly the one selected by its choice bit.
//
// Any malformed receiver message (length mismatch, invalid point, or a pair
// that would drive m_{A,j} to the point at infinity and thereby make the
// agreed key predictable) is rejected with an error.
//
// In the DKLS23 role mapping VOLE Bob calls this.
func BaseOTSenderRound2(msg *BaseOTReceiverMsg) (seeds0, seeds1 [][]byte, reply *BaseOTSenderMsg, err error) {
	if msg == nil {
		return nil, nil, nil, errors.New("dkls23 BaseOTSenderRound2: nil receiver message")
	}
	n := len(msg.R0)
	if n == 0 || len(msg.R1) != n {
		return nil, nil, nil, fmt.Errorf("dkls23 BaseOTSenderRound2: receiver message must hold the same non-zero number of r_0 and r_1 points, got %d and %d", n, len(msg.R1))
	}

	seeds0 = make([][]byte, n)
	seeds1 = make([][]byte, n)
	reply = &BaseOTSenderMsg{
		M0: make([][]byte, n),
		M1: make([][]byte, n),
	}

	for k := 0; k < n; k++ {
		var r [2]*curvePoint
		rBytes := [2][]byte{msg.R0[k], msg.R1[k]}
		for j := 0; j < 2; j++ {
			r[j], err = compressedToPoint(rBytes[j])
			if err != nil {
				return nil, nil, nil, fmt.Errorf("dkls23 BaseOTSenderRound2: invalid r_%d at instance %d: %w", j, k, err)
			}
		}

		for j := 0; j < 2; j++ {
			// m_{A,j} = r_j + H_j(r_{1-j}).
			mA := pointAdd(r[j], hashToCurve(byte(j), k, rBytes[1-j]))
			if isInfinity(mA) {
				// s_{B,j} would be the identity, a value the receiver can
				// predict without knowing b_j, so K^j_k would not be hidden.
				return nil, nil, nil, fmt.Errorf("dkls23 BaseOTSenderRound2: r_%d at instance %d yields the point at infinity", j, k)
			}

			// b_j ← Zq;  m_{B,j} = b_j·G;  s_{B,j} = b_j·m_{A,j}.
			b, e := sampleScalar()
			if e != nil {
				return nil, nil, nil, fmt.Errorf("dkls23 BaseOTSenderRound2: sampling b_%d at instance %d: %w", j, k, e)
			}
			mB, e := scalarMulGCompressed(&b)
			if e != nil {
				b.Zero()
				return nil, nil, nil, fmt.Errorf("dkls23 BaseOTSenderRound2: instance %d: %w", k, e)
			}
			sBytes, e := pointToCompressed(scalarMul(&b, mA))
			b.Zero()
			if e != nil {
				return nil, nil, nil, fmt.Errorf("dkls23 BaseOTSenderRound2: instance %d: %w", k, e)
			}
			seed := shake256Seed(k, sBytes)

			if j == 0 {
				reply.M0[k] = mB
				seeds0[k] = seed
			} else {
				reply.M1[k] = mB
				seeds1[k] = seed
			}
		}
	}
	return seeds0, seeds1, reply, nil
}

// BaseOTReceiverFinalize completes the base OT for the receiver (MR19 Figure
// 8): for each instance k it selects m_{B,c} with a constant-time copy,
// computes the agreed key s_{A,c} = a_k·m_{B,c}, and derives the OT output
// string K^c_k, which equals the sender's seeds_c[k]. The returned slice
// holds one 32-byte seed per instance.
//
// The ephemeral scalars state.A are zeroized before returning, on success and
// on error alike; a state cannot be finalized twice.
//
// In the DKLS23 role mapping VOLE Alice calls this.
func BaseOTReceiverFinalize(state *BaseOTReceiverState, reply *BaseOTSenderMsg) ([][]byte, error) {
	if state == nil {
		return nil, errors.New("dkls23 BaseOTReceiverFinalize: nil receiver state")
	}
	defer func() {
		for k := range state.A {
			state.A[k].Zero()
		}
	}()

	n := len(state.A)
	if n == 0 || len(state.Choices) != n {
		return nil, errors.New("dkls23 BaseOTReceiverFinalize: receiver state is empty or inconsistent")
	}
	if reply == nil {
		return nil, errors.New("dkls23 BaseOTReceiverFinalize: nil sender message")
	}
	if len(reply.M0) != n || len(reply.M1) != n {
		return nil, fmt.Errorf("dkls23 BaseOTReceiverFinalize: sender message must hold %d m_0 and m_1 points, got %d and %d", n, len(reply.M0), len(reply.M1))
	}

	seeds := make([][]byte, n)
	for k := 0; k < n; k++ {
		if state.A[k].IsZero() {
			return nil, fmt.Errorf("dkls23 BaseOTReceiverFinalize: receiver state at instance %d has been zeroized", k)
		}

		// Parse and validate both points before selecting, so that the
		// validation performed does not depend on the choice bit.
		m0, err := compressedToPoint(reply.M0[k])
		if err != nil {
			return nil, fmt.Errorf("dkls23 BaseOTReceiverFinalize: invalid m_0 at instance %d: %w", k, err)
		}
		m1, err := compressedToPoint(reply.M1[k])
		if err != nil {
			return nil, fmt.Errorf("dkls23 BaseOTReceiverFinalize: invalid m_1 at instance %d: %w", k, err)
		}

		// s_{A,c} = a·m_{B,c}.
		c := int(condUint32(state.Choices[k]))
		mBc, err := selectPoint(c, m0, m1)
		if err != nil {
			return nil, fmt.Errorf("dkls23 BaseOTReceiverFinalize: select point: %w", err)
		}
		sBytes, err := pointToCompressed(scalarMul(&state.A[k], mBc))
		if err != nil {
			// Unreachable for a valid state: a ≠ 0 and m_{B,c} ≠ O in a
			// prime-order group.
			return nil, fmt.Errorf("dkls23 BaseOTReceiverFinalize: instance %d: %w", k, err)
		}
		seeds[k] = shake256Seed(k, sBytes)
	}
	return seeds, nil
}
