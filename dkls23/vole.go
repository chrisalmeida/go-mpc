package dkls23

import (
	"crypto/subtle"
	"errors"

	"github.com/btcsuite/btcd/btcec/v2"
	"golang.org/x/crypto/sha3"
)

// --- RVOLE: Random Vector OLE per DKLS23 Protocol 5.2 ---
//
// VOLE produces correlated randomness (chi, c, d) such that c + d = a * chi mod q,
// where Alice holds (a, c) and Bob holds (chi, d).
// The VOLE is instantiated via IKNP OT extension with LambdaC base OTs and Xi extension OTs.

// VOLEBobState holds Bob's sampling phase output from OTE.
// Bob's input is beta ∈ {0,1}^Xi; chi = <g, beta> mod q is the scalar correlation.
type VOLEBobState struct {
	// Beta is Bob's random binary vector (OTE input).
	Beta [Xi]bool
	// Chi = GadgetInnerProduct(Beta) mod q; this is Bob's correlated scalar.
	Chi btcec.ModNScalar
	// Gamma contains the received OTE values gamma[j][i] for j ∈ [Xi], i ∈ [Ell+Rho].
	Gamma [][Ell + Rho][32]byte
}

// VOLEAliceState holds Alice's state after OTE expansion.
// Alice's outputs c_u, c_v are her VOLE output shares (set during multiply phase).
type VOLEAliceState struct {
	// Alpha0, Alpha1 are Alice's OTE sender output pairs.
	Alpha0, Alpha1 [][Ell + Rho][32]byte
	// C_u, C_v are Alice's VOLE output shares (filled in during VOLEAliceMultiply).
	C_u, C_v btcec.ModNScalar
}

// VOLEMultiplyMsg is Alice's message to Bob during the multiply phase (paper Protocol 5.2, step 3).
type VOLEMultiplyMsg struct {
	// SID is the session identifier for this VOLE instance.
	SID string
	// ATilde[j][i] are the derandomized OT messages for j ∈ [Xi], i ∈ [Ell+Rho].
	ATilde [Xi][Ell + Rho][32]byte
	// Eta[k] are the check scalars for the Fiat-Shamir proof, k ∈ [Rho].
	Eta [Rho][32]byte
	// Mu is the VOLE proof hash (constant-time checked by Bob).
	Mu [32]byte
}

// voleFiatShamir computes the Fiat-Shamir challenges theta[i][k] ∈ Zq
// for i ∈ [Ell], k ∈ [Rho] from the session ID and aTilde matrix.
// Uses SHAKE256("vole-fs" || sid || aTilde_bytes) and reads Ell*Rho scalars.
// The challenges are public values derived from public data.
func voleFiatShamir(sid string, aTilde [Xi][Ell + Rho][32]byte) [Ell][Rho]btcec.ModNScalar {
	h := sha3.NewShake256()
	h.Write([]byte(domainVOLEFS))
	h.Write([]byte(sid))
	for j := 0; j < Xi; j++ {
		for i := 0; i < Ell+Rho; i++ {
			h.Write(aTilde[j][i][:])
		}
	}

	var theta [Ell][Rho]btcec.ModNScalar
	for i := 0; i < Ell; i++ {
		for k := 0; k < Rho; k++ {
			raw := make([]byte, 64)
			h.Read(raw)
			theta[i][k] = reduce64Public(raw)
		}
	}
	return theta
}

// voleProofHash computes SHAKE256("vole-proof" || sid || muTilde_bytes) → 32 bytes.
func voleProofHash(sid string, muTilde [Xi][Rho][32]byte) [32]byte {
	h := sha3.NewShake256()
	h.Write([]byte(domainVOLEProof))
	h.Write([]byte(sid))
	for j := 0; j < Xi; j++ {
		for k := 0; k < Rho; k++ {
			h.Write(muTilde[j][k][:])
		}
	}
	var out [32]byte
	h.Read(out[:])
	return out
}

// VOLEBobSample computes Bob's VOLE sampling phase output from OTE values.
// Bob's binary input beta and the OTE values gamma determine his VOLE output.
// chi = GadgetInnerProduct(beta) is the scalar that will multiply Alice's input.
// This corresponds to Protocol 5.2, Bob's sampling step.
func VOLEBobSample(gamma [][Ell + Rho][32]byte, beta [Xi]bool) (*VOLEBobState, error) {
	if len(gamma) != Xi {
		return nil, errors.New("dkls23 VOLEBobSample: gamma must have Xi entries")
	}
	chi := GadgetInnerProduct(beta)
	return &VOLEBobState{
		Beta:  beta,
		Chi:   chi,
		Gamma: gamma,
	}, nil
}

// VOLEAliceSetup computes Alice's random VOLE output shares from OTE sender values.
// Alice's output shares are:
//
//	c_u = -sum_{j∈[Xi]} g[j] * alpha0[j][0] mod q
//	c_v = -sum_{j∈[Xi]} g[j] * alpha0[j][1] mod q
//
// This corresponds to Protocol 5.2, Alice's setup step.
func VOLEAliceSetup(alpha0, alpha1 [][Ell + Rho][32]byte) (*VOLEAliceState, error) {
	if len(alpha0) != Xi || len(alpha1) != Xi {
		return nil, errors.New("dkls23 VOLEAliceSetup: alpha0 and alpha1 must have Xi entries")
	}
	var c_u, c_v btcec.ModNScalar
	for j := 0; j < Xi; j++ {
		var a0j0, a0j1 btcec.ModNScalar
		a0j0.SetByteSlice(alpha0[j][0][:])
		a0j1.SetByteSlice(alpha0[j][1][:])
		var term_u, term_v btcec.ModNScalar
		term_u.Mul2(&gadget[j], &a0j0)
		term_v.Mul2(&gadget[j], &a0j1)
		c_u.Add(&term_u)
		c_v.Add(&term_v)
	}
	c_u.Negate()
	c_v.Negate()

	return &VOLEAliceState{
		Alpha0: alpha0,
		Alpha1: alpha1,
		C_u:    c_u,
		C_v:    c_v,
	}, nil
}

// VOLEAliceMultiply executes Alice's multiply phase (paper Protocol 5.2, Alice step 3).
// Alice's inputs are r_i (nonce scalar) and sk_i (key scalar).
// Returns Alice's output shares c_u, c_v and the message to send to Bob.
//
// For each j ∈ [Xi], i ∈ [Ell+Rho]:
//   - aTilde[j][i] = alpha0[j][i] - alpha1[j][i] + a[i] mod q
//     (where a[0]=r_i, a[1]=sk_i; check elements a[Ell..Ell+Rho-1] are freshly sampled)
//
// A Fiat-Shamir proof (eta, mu) is attached to enable Bob to verify correctness.
func VOLEAliceMultiply(state *VOLEAliceState, sid string, r_i, sk_i *btcec.ModNScalar) (c_u, c_v btcec.ModNScalar, msg *VOLEMultiplyMsg, err error) {
	var a [Ell + Rho]btcec.ModNScalar
	a[0].Set(r_i)
	a[1].Set(sk_i)

	// Sample random check elements aHat[k] for k ∈ [Rho].
	var aHat [Rho]btcec.ModNScalar
	for k := 0; k < Rho; k++ {
		aHat[k], err = sampleScalar()
		if err != nil {
			return
		}
		a[Ell+k].Set(&aHat[k])
	}

	// Compute aTilde[j][i] = alpha0[j][i] - alpha1[j][i] + a[i] mod q.
	var aTilde [Xi][Ell + Rho][32]byte
	for j := 0; j < Xi; j++ {
		for i := 0; i < Ell+Rho; i++ {
			var a0, a1 btcec.ModNScalar
			a0.SetByteSlice(state.Alpha0[j][i][:])
			a1.SetByteSlice(state.Alpha1[j][i][:])
			var v btcec.ModNScalar
			v.NegateVal(&a1) // v = -a1
			v.Add(&a0)       // v = a0 - a1
			v.Add(&a[i])     // v = a0 - a1 + a[i]
			aTilde[j][i] = v.Bytes()
		}
	}

	// Fiat-Shamir: theta[i][k] for i ∈ [Ell], k ∈ [Rho].
	theta := voleFiatShamir(sid, aTilde)

	// Compute eta[k] = aHat[k] + sum_{i∈[Ell]} theta[i][k] * a[i] mod q.
	var eta [Rho][32]byte
	for k := 0; k < Rho; k++ {
		var etaK btcec.ModNScalar
		etaK.Set(&aHat[k])
		for i := 0; i < Ell; i++ {
			var term btcec.ModNScalar
			term.Mul2(&theta[i][k], &a[i])
			etaK.Add(&term)
		}
		eta[k] = etaK.Bytes()
	}

	for k := 0; k < Rho; k++ {
		aHat[k].Zero()
	}

	// Compute muTilde[j][k] = alpha0[j][Ell+k] + sum_{i∈[Ell]} theta[i][k] * alpha0[j][i] mod q.
	var muTilde [Xi][Rho][32]byte
	for j := 0; j < Xi; j++ {
		for k := 0; k < Rho; k++ {
			var v btcec.ModNScalar
			v.SetByteSlice(state.Alpha0[j][Ell+k][:])
			for i := 0; i < Ell; i++ {
				var a0ji btcec.ModNScalar
				a0ji.SetByteSlice(state.Alpha0[j][i][:])
				var term btcec.ModNScalar
				term.Mul2(&theta[i][k], &a0ji)
				v.Add(&term)
			}
			muTilde[j][k] = v.Bytes()
		}
	}

	mu := voleProofHash(sid, muTilde)

	// Alice's output shares were computed from alpha0 sums during setup.
	c_u = state.C_u
	c_v = state.C_v

	msg = &VOLEMultiplyMsg{
		SID:    sid,
		ATilde: aTilde,
		Eta:    eta,
		Mu:     mu,
	}
	return
}

// VOLEBobReceive executes Bob's receive phase (paper Protocol 5.2, Bob step 4).
// Bob verifies Alice's proof and computes his VOLE output shares d_u, d_v.
// Returns error if the proof check fails (which indicates Alice cheated).
//
// The check uses constant-time comparison for mu to prevent timing attacks.
func VOLEBobReceive(state *VOLEBobState, sid string, msg *VOLEMultiplyMsg) (d_u, d_v btcec.ModNScalar, err error) {
	// Recompute theta from the aTilde matrix Alice sent.
	theta := voleFiatShamir(sid, msg.ATilde)

	// Compute dDot[j][i] = gamma[j][i] + beta[j]*aTilde[j][i] mod q.
	// Branchless: multiply aTilde by 0-or-1 mask derived from Beta.
	dDot := make([][Ell + Rho]btcec.ModNScalar, Xi)
	for j := 0; j < Xi; j++ {
		var betaMask btcec.ModNScalar
		betaMask.SetInt(condUint32(state.Beta[j]))
		for i := 0; i < Ell+Rho; i++ {
			var v btcec.ModNScalar
			v.SetByteSlice(state.Gamma[j][i][:])
			var atji btcec.ModNScalar
			atji.SetByteSlice(msg.ATilde[j][i][:])
			atji.Mul(&betaMask) // 0 or aTilde[j][i]
			v.Add(&atji)
			dDot[j][i] = v
		}
	}

	// Compute muPrime[j][k] = dDot[j][Ell+k] + sum_{i∈[Ell]} theta[i][k]*dDot[j][i] - beta[j]*eta[k] mod q.
	// Branchless: multiply negated eta by the same 0-or-1 Beta mask.
	var muPrime [Xi][Rho][32]byte
	for j := 0; j < Xi; j++ {
		var betaMask btcec.ModNScalar
		betaMask.SetInt(condUint32(state.Beta[j]))
		for k := 0; k < Rho; k++ {
			v := dDot[j][Ell+k]
			for i := 0; i < Ell; i++ {
				dd := dDot[j][i]
				var term btcec.ModNScalar
				term.Mul2(&theta[i][k], &dd)
				v.Add(&term)
			}
			var etaK btcec.ModNScalar
			etaK.SetByteSlice(msg.Eta[k][:])
			etaK.Negate()       // -eta[k]
			etaK.Mul(&betaMask) // 0 or -eta[k]
			v.Add(&etaK)
			muPrime[j][k] = v.Bytes()
		}
	}

	// Verify proof: SHAKE256("vole-proof" || sid || muPrime_bytes) == mu.
	computedMu := voleProofHash(sid, muPrime)
	if subtle.ConstantTimeCompare(computedMu[:], msg.Mu[:]) != 1 {
		return btcec.ModNScalar{}, btcec.ModNScalar{}, errors.New("dkls23 VOLEBobReceive: proof verification failed")
	}

	// Compute d_u = sum_{j∈[Xi]} g[j] * dDot[j][0] mod q.
	// Compute d_v = sum_{j∈[Xi]} g[j] * dDot[j][1] mod q.
	for j := 0; j < Xi; j++ {
		dd0, dd1 := dDot[j][0], dDot[j][1]
		var term_u, term_v btcec.ModNScalar
		term_u.Mul2(&gadget[j], &dd0)
		term_v.Mul2(&gadget[j], &dd1)
		d_u.Add(&term_u)
		d_v.Add(&term_v)
	}
	return
}
