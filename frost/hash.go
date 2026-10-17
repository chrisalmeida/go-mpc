package frost

import (
	"crypto/sha512"

	"filippo.io/edwards25519"
)

// Hash functions.
//
// H1-H5 are the FROST(Ed25519, SHA-512) hash functions of RFC 9591
// Section 6.1. hashDKGProof is NOT from RFC 9591: the RFC does not specify
// a distributed key generation protocol, so it is this package's
// instantiation of the hash H used by the proof of knowledge in the FROST
// paper's KeyGen (Komlo-Goldberg, Figure 1), built in the same style as
// H1/H3 (SHA-512 over ContextString || tag || input, reduced mod L).

// Domain separation tags for the hash functions.
const (
	domainRho   = "rho"
	domainNonce = "nonce"
	domainMsg   = "msg"
	domainCom   = "com"
	// domainDKG is this package's tag for the DKG proof-of-knowledge hash.
	// It is not defined by RFC 9591 (see hashDKGProof).
	domainDKG = "dkg"
)

// H1 maps arbitrary data to a Scalar. Domain: "rho" (binding factor derivation).
//
//	H1(m) = SHA-512(ContextString || "rho" || m) mod L
//
// (RFC 9591 Section 6.1, H1)
func H1(msg []byte) *edwards25519.Scalar {
	prefix := []byte(ContextString + domainRho)
	return hashToScalar(prefix, msg)
}

// H2 computes the challenge scalar per RFC 8032: NO domain prefix.
//
//	H2(m) = SHA-512(m) mod L
//
// This is the standard Ed25519 challenge hash to ensure RFC 8032 compatibility.
// The input m is typically R_encoded || PK_encoded || msg.
// (RFC 9591 Section 6.1, H2)
func H2(msg []byte) *edwards25519.Scalar {
	return hashToScalar(nil, msg)
}

// H3 maps arbitrary data to a Scalar. Domain: "nonce" (nonce derivation).
//
//	H3(m) = SHA-512(ContextString || "nonce" || m) mod L
//
// (RFC 9591 Section 6.1, H3)
func H3(msg []byte) *edwards25519.Scalar {
	prefix := []byte(ContextString + domainNonce)
	return hashToScalar(prefix, msg)
}

// H4 hashes arbitrary data to a byte string. Domain: "msg" (message hash).
//
//	H4(m) = SHA-512(ContextString || "msg" || m)
//
// (RFC 9591 Section 6.1, H4)
func H4(msg []byte) []byte {
	return hashToBytes([]byte(ContextString+domainMsg), msg)
}

// H5 hashes arbitrary data to a byte string. Domain: "com" (commitment hash).
//
//	H5(m) = SHA-512(ContextString || "com" || m)
//
// (RFC 9591 Section 6.1, H5)
func H5(msg []byte) []byte {
	return hashToBytes([]byte(ContextString+domainCom), msg)
}

// hashDKGProof computes the challenge c_i for the DKG proof of knowledge of
// a_i0 (FROST paper, Figure 1, Round 1 step 2: c_i = H(i, Φ, φ_i0, R_i)).
//
// RFC 9591 does not specify a DKG, so this is this package's instantiation
// of the paper's H, in the style of the RFC's H1/H3:
//
//	c_i = SHA-512(ContextString || "dkg" || SerializeScalar(i) || Φ || φ_i0 || R_i) mod L
//
// where i is the party identifier serialized as a 32-byte little-endian
// scalar, Φ is the caller-supplied context string (DKGPartyConfig.Context),
// φ_i0 is the 32-byte encoding of a_i0·B and R_i is the 32-byte encoding of
// the proof commitment k·B. Φ is the only variable-length input and the
// elements that follow it are fixed-length, so the encoding is unambiguous.
func hashDKGProof(id int, context []byte, phi0 []byte, R []byte) *edwards25519.Scalar {
	prefix := []byte(ContextString + domainDKG)
	idBytes := serializeScalarID(id)
	input := make([]byte, 0, len(idBytes)+len(context)+len(phi0)+len(R))
	input = append(input, idBytes...)
	input = append(input, context...)
	input = append(input, phi0...)
	input = append(input, R...)
	return hashToScalar(prefix, input)
}

// hashToScalar computes SHA-512(prefix || msg) and reduces mod L.
// If prefix is nil (H2), only msg is hashed.
func hashToScalar(prefix []byte, msg []byte) *edwards25519.Scalar {
	h := sha512.New()
	if prefix != nil {
		h.Write(prefix)
	}
	h.Write(msg)
	digest := h.Sum(nil) // 64 bytes

	s, err := edwards25519.NewScalar().SetUniformBytes(digest)
	if err != nil {
		// SetUniformBytes only fails if len != 64, which cannot happen with SHA-512.
		panic("frost: SHA-512 produced non-64-byte output")
	}
	return s
}

// hashToBytes computes SHA-512(prefix || msg) and returns the 64-byte digest.
func hashToBytes(prefix []byte, msg []byte) []byte {
	h := sha512.New()
	if prefix != nil {
		h.Write(prefix)
	}
	h.Write(msg)
	return h.Sum(nil)
}
