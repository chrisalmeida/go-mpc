package frost

import (
	"filippo.io/edwards25519"
)

// Verify checks a FROST Ed25519 signature (R, z) against the group public key.
//
// RFC 9591 Section 6.1 defines verification for this ciphersuite as
// "specified in Section 5.1.7 of [RFC8032] with the constraint that
// implementations MUST check the group equation [8][z]B = [8]R + [8][c]PK".
// Verify therefore does exactly what RFC 8032 Section 5.1.7 does for its
// inputs, plus the cofactored equation:
//
//   - R and PK are decoded per RFC 8032 Section 5.1.3 (decodePoint). A
//     non-canonical encoding (y >= p, or x = 0 with the sign bit set) is a
//     decoding failure and the signature is invalid. RFC 8032 decoding does
//     not reject the identity or small-order points, so neither does Verify;
//     the cofactored equation makes the outcome independent of any
//     small-order component. (The stricter DeserializeElement of RFC 9591
//     Section 6.1 applies to protocol messages, not to signature
//     verification; see deserializeElement.)
//   - z must be a canonical scalar in [0, L-1]; otherwise the signature is
//     invalid.
//   - c = H2(R || PK || msg) = SHA-512(R || PK || msg) mod L, the RFC 8032
//     challenge; H2 has no domain separator precisely so that this matches.
//
// Signatures produced by Aggregate (and any RFC 8032 signature) are also
// accepted by crypto/ed25519.Verify: honestly generated R and PK are
// canonical encodings of prime-order points, for which the cofactored and
// non-cofactored equations agree.
func Verify(publicKey []byte, message []byte, sig *Signature) bool {
	if len(sig.R) != ElementLen || len(sig.Z) != ScalarLen || len(publicKey) != ElementLen {
		return false
	}

	R, err := decodePoint(sig.R)
	if err != nil {
		return false
	}
	z, err := edwards25519.NewScalar().SetCanonicalBytes(sig.Z)
	if err != nil {
		return false
	}
	PK, err := decodePoint(publicKey)
	if err != nil {
		return false
	}

	// c = H2(R || PK || msg) — standard Ed25519 challenge (no domain prefix).
	input := make([]byte, 0, ElementLen+ElementLen+len(message))
	input = append(input, sig.R...)
	input = append(input, publicKey...)
	input = append(input, message...)
	c := H2(input)

	// Cofactored verification: [8]([z]B) == [8](R + [c]PK)
	cofactor := scalarFromUint64(8)

	// LHS = [8][z]B
	zB := edwards25519.NewGeneratorPoint().ScalarBaseMult(z)
	lhs := edwards25519.NewIdentityPoint().ScalarMult(cofactor, zB)

	// RHS = [8](R + [c]PK)
	cPK := edwards25519.NewIdentityPoint().ScalarMult(c, PK)
	rCPK := edwards25519.NewIdentityPoint().Add(R, cPK)
	rhs := edwards25519.NewIdentityPoint().ScalarMult(cofactor, rCPK)

	return lhs.Equal(rhs) == 1
}

// VerifyBytes verifies a 64-byte Ed25519 signature (R || z) with Verify.
func VerifyBytes(publicKey []byte, message []byte, sigBytes []byte) bool {
	if len(sigBytes) != 64 {
		return false
	}
	sig := &Signature{
		R: sigBytes[:32],
		Z: sigBytes[32:],
	}
	return Verify(publicKey, message, sig)
}
