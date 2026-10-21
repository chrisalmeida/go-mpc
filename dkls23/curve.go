package dkls23

import (
	"crypto/subtle"
	"errors"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/bytemare/secp256k1"
)

// curvePoint uses complete point addition and constant-time scalar
// multiplication. These are the same secp256k1 group operations required by
// DKLS23 Protocols 3.6 and 7.1 and MR19 Figure 8 / Appendix D.1; encodings,
// hash inputs, and protocol equations are unchanged.
type curvePoint = secp256k1.Element

func newCurvePoint() *curvePoint { return secp256k1.NewElement() }

// curveScalar converts a canonical btcec scalar without math/big. Bytes always
// returns exactly 32 bytes encoding a value below q, so Decode cannot fail.
// This helper is never used to decode received, unvalidated scalar bytes.
func curveScalar(s *btcec.ModNScalar) *secp256k1.Scalar {
	encoded := s.Bytes()
	defer clear(encoded[:])
	result := secp256k1.NewScalar()
	_ = result.Decode(encoded[:])
	return result
}

// scalarMulG computes s*G with the backend's fixed 256-bit ladder.
func scalarMulG(s *btcec.ModNScalar) *curvePoint {
	scalar := curveScalar(s)
	defer scalar.Zero()
	return newCurvePoint().Base().Multiply(scalar)
}

// scalarMulGCompressed computes s*G in the protocol's compressed SEC1 encoding.
func scalarMulGCompressed(s *btcec.ModNScalar) ([]byte, error) {
	return pointToCompressed(scalarMulG(s))
}

// scalarMul computes s*P with the same fixed ladder, including when P was
// selected using a secret OT choice bit. The input point is not modified.
func scalarMul(s *btcec.ModNScalar, p *curvePoint) *curvePoint {
	scalar := curveScalar(s)
	defer scalar.Zero()
	return p.Copy().Multiply(scalar)
}

func pointAdd(p, q *curvePoint) *curvePoint { return p.Copy().Add(q) }
func pointNeg(p *curvePoint) *curvePoint    { return newCurvePoint().Subtract(p) }
func pointSub(p, q *curvePoint) *curvePoint { return p.Copy().Subtract(q) }
func isInfinity(p *curvePoint) bool         { return p.IsIdentity() }

// pointToCompressed serializes in constant time, including the parity bit of
// secret Diffie-Hellman points (MR19 Appendix D.1). Infinity is not a valid
// protocol message or agreed key and is rejected, as before.
func pointToCompressed(p *curvePoint) ([]byte, error) {
	encoded := p.Encode()
	if len(encoded) != compressedPointLen {
		return nil, errors.New("dkls23: cannot serialize point at infinity")
	}
	return encoded, nil
}

// compressedToPoint validates the protocol's 33-byte compressed SEC1 points.
// Decoding is only for public input, never for secret scalars or agreed keys.
func compressedToPoint(encoded []byte) (*curvePoint, error) {
	p := newCurvePoint()
	if err := p.DecodeCompressed(encoded); err != nil {
		return nil, err
	}
	return p, nil
}

// selectPoint selects finite p0 or p1 without control flow or memory access
// depending on c. Both points must already have been validated. Uncompressed
// coordinates avoid decompressing a point selected by a secret choice bit.
func selectPoint(c int, p0, p1 *curvePoint) (*curvePoint, error) {
	encoded := p0.EncodeUncompressed()
	other := p1.EncodeUncompressed()
	subtle.ConstantTimeCopy(c, encoded, other)
	result := newCurvePoint()
	if err := result.DecodeUncompressed(encoded); err != nil {
		return nil, err
	}
	return result, nil
}
