package dkls23

import "encoding/binary"

// --- GF(2^128) arithmetic for the KOS15 OT-extension consistency check ---
//
// Elements are polynomials over GF(2) of degree < 128, reduced modulo the
// standard irreducible polynomial
//
//	x^128 + x^7 + x^2 + x + 1.
//
// Bit-order convention: byte i, bit b (LSB-first within the byte) represents
// the coefficient of x^{8i+b}. Hence x^0 is byte 0 bit 0 (0x01 in byte 0),
// x^64 is byte 8 bit 0, and x^127 is byte 15 bit 7. Addition is XOR.
//
// gf128Mul is bit-serial shift-and-add and is constant time with respect to
// both operands: there are no data-dependent branches or memory accesses;
// every conditional is realized with a full-width mask.

// gf128 is an element of GF(2^128) in the byte/bit order described above.
type gf128 [16]byte

// gf128Reduction is the low word of x^128 mod (x^128 + x^7 + x^2 + x + 1),
// i.e. x^7 + x^2 + x + 1 = 0x87.
const gf128Reduction uint64 = 0x87

// gf128Mul returns a*b in GF(2^128). Constant time in both operands.
func gf128Mul(a, b gf128) gf128 {
	// Split into two little-endian 64-bit limbs: lo holds x^0..x^63, hi holds x^64..x^127.
	aLo := binary.LittleEndian.Uint64(a[0:8])
	aHi := binary.LittleEndian.Uint64(a[8:16])
	bLo := binary.LittleEndian.Uint64(b[0:8])
	bHi := binary.LittleEndian.Uint64(b[8:16])

	var accLo, accHi uint64
	// Process the 64 bits of each limb of b in turn (low limb first so that
	// a is multiplied by x exactly i times before being conditionally added
	// for bit i). The shift amounts are loop constants, so the only
	// data-dependent quantities are folded into full-width masks.
	for _, limb := range [2]uint64{bLo, bHi} {
		for i := 0; i < 64; i++ {
			mask := -((limb >> uint(i)) & 1) // 0x0000... or 0xFFFF...

			accLo ^= aLo & mask
			accHi ^= aHi & mask

			// a <- a * x (shift left by one with reduction of x^128).
			carry := aHi >> 63
			aHi = (aHi << 1) | (aLo >> 63)
			aLo <<= 1
			aLo ^= gf128Reduction & (-carry)
		}
	}

	var out gf128
	binary.LittleEndian.PutUint64(out[0:8], accLo)
	binary.LittleEndian.PutUint64(out[8:16], accHi)
	return out
}

// gf128MulBit returns v if bit is 1 and the zero element if bit is 0, without
// branching on bit. Used to accumulate Σ x_j · χ_j for secret bits x_j.
func gf128MulBit(v gf128, bit byte) gf128 {
	mask := -(bit & 1) // 0x00 or 0xFF
	var out gf128
	for i := range out {
		out[i] = v[i] & mask
	}
	return out
}

// gf128Xor returns a XOR b (addition in GF(2^128)).
func gf128Xor(a, b gf128) gf128 {
	var out gf128
	for i := range out {
		out[i] = a[i] ^ b[i]
	}
	return out
}
