// Package frost implements the FROST threshold Schnorr signature protocol
// for Ed25519 as specified in RFC 9591 (FROST(Ed25519, SHA-512)).
//
// # Protocol components
//
//   - 2-round distributed key generation: Pedersen/Feldman VSS DKG with a
//     Schnorr proof of knowledge of each party's constant term, following
//     Figure 1 of the FROST paper (Komlo-Goldberg, ePrint 2020/852). RFC 9591
//     does not specify a DKG; see [DKGRound1] for the paper reference.
//   - 2-round threshold signing (RFC 9591 Section 5.1 and Section 5.2)
//   - Signature aggregation and share verification (RFC 9591 Section 5.3)
//   - Proactive key share refresh (zero-constant polynomial Feldman VSS)
//
// # Ciphersuite
//
// FROST-ED25519-SHA512-v1 (RFC 9591 Section 6.1). The test suite checks the
// implementation against the RFC 9591 Appendix E.1 test vectors.
//
// Signatures are verified with the cofactored equation
// [8][z]B = [8]R + [8][c]PK required by RFC 9591 Section 6.1, after decoding
// R and PK per RFC 8032 Section 5.1.3 (non-canonical encodings are rejected).
// Honestly generated signatures are also accepted by crypto/ed25519.Verify
// (RFC 8032 compatible).
//
// # Input validation
//
// RFC 9591 Section 5 requires every Element received over the network to be
// deserialized with DeserializeElement, which for this ciphersuite
// (Section 6.1) decodes per RFC 8032 Section 5.1.3 and additionally rejects
// the identity element and points outside the prime-order subgroup. This
// package applies that validation to all received elements: Feldman
// commitments, DKG proof commitments, nonce commitments D_i/E_i,
// verification shares, and the group public key used in signing and
// aggregation. Scalars received over the network are rejected unless they are
// canonical (in [0, L-1]).
//
// # Security model
//
// The protocol operates in a t-of-n threshold setting over the Ed25519
// curve (edwards25519). All secret scalar arithmetic uses constant-time
// operations via filippo.io/edwards25519. Cheating parties are detected
// during DKG proof and share verification and during signature share
// verification. Per RFC 9591 Section 7 the Coordinator is not trusted with
// private information but is assumed not to mount a denial of service; see
// [Aggregate] and [SignerState] before treating a share verification failure
// as proof that the named signer cheated.
//
// # Concurrency
//
// [SignerState] is safe for concurrent reads (parallel signing sessions).
// Mutating operations acquire a write lock internally.
//
// # Usage flow
//
// DKG (2 rounds + finalize) -> signing (2 rounds + aggregate) -> verify -> optional refresh.
package frost

import (
	"crypto/subtle"
	"errors"
	"fmt"

	"filippo.io/edwards25519"
)

// Ciphersuite constants per RFC 9591 Section 6.1.
const (
	// ContextString is the FROST ciphersuite identifier (RFC 9591 Section 6.1).
	ContextString = "FROST-ED25519-SHA512-v1"

	// ScalarLen is the byte length of an Ed25519 scalar (little-endian).
	ScalarLen = 32

	// ElementLen is the byte length of a compressed Edwards25519 point.
	ElementLen = 32

	// SaltLen is the byte length of commitment salts: 2*128/8 = 32 bytes.
	SaltLen = 32
)

// maxPartyID caps party identifiers to prevent overflow in Lagrange arithmetic.
const maxPartyID = 1<<31 - 1

// orderMinus2 is L-2 for the Ed25519 group order, used by scalarInverse.
// L   = 2^252 + 27742317777372353535851937790883648493
// L   = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED (big-endian)
// L-2 = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3EB (big-endian)
//
// Stored as 32 bytes little-endian (Ed25519 native encoding):
var orderMinus2 = [32]byte{
	0xeb, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
	0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
}

// scalarInverse computes val^(-1) mod L in constant time using Fermat's
// little theorem: a^(-1) = a^(L-2) mod L for prime L.
//
// The exponent L-2 is a public constant, so the square-and-multiply
// loop's branch pattern is fixed and leaks no information about val.
func scalarInverse(val *edwards25519.Scalar) *edwards25519.Scalar {
	// Convert L-2 to big-endian for bit scanning.
	var expBE [32]byte
	for i := 0; i < 32; i++ {
		expBE[i] = orderMinus2[31-i]
	}

	result := edwards25519.NewScalar()
	one := scalarFromUint64(1)
	result.Set(one)

	for i := 0; i < 32; i++ {
		for bit := 7; bit >= 0; bit-- {
			result.Multiply(result, result)
			if (expBE[i]>>uint(bit))&1 == 1 {
				result.Multiply(result, val)
			}
		}
	}
	return result
}

// scalarFromUint64 creates a Scalar from a uint64 value.
func scalarFromUint64(v uint64) *edwards25519.Scalar {
	var buf [32]byte
	buf[0] = byte(v)
	buf[1] = byte(v >> 8)
	buf[2] = byte(v >> 16)
	buf[3] = byte(v >> 24)
	buf[4] = byte(v >> 32)
	buf[5] = byte(v >> 40)
	buf[6] = byte(v >> 48)
	buf[7] = byte(v >> 56)
	s, _ := edwards25519.NewScalar().SetCanonicalBytes(buf[:])
	return s
}

// scalarFromInt creates a Scalar from a positive int.
func scalarFromInt(v int) *edwards25519.Scalar {
	return scalarFromUint64(uint64(v))
}

// Element decoding errors.
var (
	errElementLength       = errors.New("frost: element encoding must be 32 bytes")
	errElementNonCanonical = errors.New("frost: non-canonical element encoding (RFC 8032 Section 5.1.3)")
	errElementIdentity     = errors.New("frost: element is the group identity")
	errElementSmallOrder   = errors.New("frost: element is not in the prime-order subgroup")
)

// decodePoint decodes a 32-byte point encoding exactly as RFC 8032
// Section 5.1.3 requires: the y-coordinate must be in [0, p-1] (so y >= p is
// rejected), x is recovered from y, and an encoding with x = 0 and the sign
// bit set is rejected. The identity and small-order points are accepted,
// because RFC 8032 decoding accepts them; use deserializeElement for the
// stricter RFC 9591 DeserializeElement.
//
// filippo.io/edwards25519's Point.SetBytes accepts all non-canonical encodings
// of valid points, so canonicity is enforced by re-encoding the decoded point
// and requiring the result to equal the input bytes. Both non-canonical cases
// above re-encode differently (y is reduced mod p; x = 0 re-encodes with sign
// bit 0), so this comparison is equivalent to the RFC 8032 rules.
func decodePoint(b []byte) (*edwards25519.Point, error) {
	if len(b) != ElementLen {
		return nil, errElementLength
	}
	p, err := edwards25519.NewIdentityPoint().SetBytes(b)
	if err != nil {
		return nil, fmt.Errorf("frost: invalid element encoding: %w", err)
	}
	if subtle.ConstantTimeCompare(p.Bytes(), b) != 1 {
		return nil, errElementNonCanonical
	}
	return p, nil
}

// deserializeElement implements DeserializeElement for FROST(Ed25519, SHA-512)
// (RFC 9591 Section 6.1): decode per RFC 8032 Section 5.1.3 (decodePoint),
// then reject the group identity element and any point that is not in the
// prime-order subgroup. The subgroup check multiplies the point by the group
// order L and requires the result to be the identity, as the RFC describes.
//
// Every Element received from another party MUST be parsed with this function
// (RFC 9591 Section 5).
func deserializeElement(b []byte) (*edwards25519.Point, error) {
	p, err := decodePoint(b)
	if err != nil {
		return nil, err
	}
	identity := edwards25519.NewIdentityPoint()
	if p.Equal(identity) == 1 {
		return nil, errElementIdentity
	}
	// [L]P must be the identity. L itself is 0 as an edwards25519.Scalar
	// (Scalars are reduced mod L), so compute [L]P as [L-1]P + P with
	// L-1 = -1 mod L.
	lMinus1 := edwards25519.NewScalar().Subtract(edwards25519.NewScalar(), scalarFromUint64(1))
	lp := edwards25519.NewIdentityPoint().ScalarMult(lMinus1, p)
	lp.Add(lp, p)
	if lp.Equal(identity) != 1 {
		return nil, errElementSmallOrder
	}
	return p, nil
}
