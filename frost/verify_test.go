package frost

import (
	"crypto/ed25519"
	"testing"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyInvalidInputs(t *testing.T) {
	t.Parallel()

	// Wrong-length public key.
	assert.False(t, Verify([]byte{1, 2, 3}, []byte("msg"), &Signature{R: make([]byte, 32), Z: make([]byte, 32)}))

	// Wrong-length R.
	assert.False(t, Verify(make([]byte, 32), []byte("msg"), &Signature{R: make([]byte, 31), Z: make([]byte, 32)}))

	// Wrong-length Z.
	assert.False(t, Verify(make([]byte, 32), []byte("msg"), &Signature{R: make([]byte, 32), Z: make([]byte, 31)}))
}

func TestVerifyBytesCompat(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	msg := []byte("verify bytes test")

	sig := fullSign(t, keyShares, []int{1, 2, 3}, msg)

	// VerifyBytes should work.
	assert.True(t, VerifyBytes(keyShares[1].PublicKey, msg, sig.Bytes()))

	// Wrong length should fail.
	assert.False(t, VerifyBytes(keyShares[1].PublicKey, msg, make([]byte, 63)))
}

func TestVerifyCofactored(t *testing.T) {
	t.Parallel()
	// Generate a standard Ed25519 key and sign.
	pub, priv, _ := ed25519.GenerateKey(nil)
	msg := []byte("standard ed25519 signature")
	stdSig := ed25519.Sign(priv, msg)

	// Our cofactored verifier should also accept standard Ed25519 sigs
	// (well-formed sigs are in the prime-order subgroup, so cofactored
	// verification agrees with standard verification).
	sig := &Signature{R: stdSig[:32], Z: stdSig[32:]}
	assert.True(t, Verify([]byte(pub), msg, sig))
}

func TestVerifyWrongMessage(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	sig := fullSign(t, keyShares, []int{1, 2, 3}, []byte("correct"))
	assert.False(t, Verify(keyShares[1].PublicKey, []byte("wrong"), sig))
}

func TestVerifyWrongPublicKey(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	msg := []byte("test")
	sig := fullSign(t, keyShares, []int{1, 2, 3}, msg)

	// Generate a different key.
	otherShares, err := buildDKG([]int{1, 2, 3}, 3)
	assert.NoError(t, err)
	assert.False(t, Verify(otherShares[1].PublicKey, msg, sig))
}

func TestVerifyCorruptedR(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	msg := []byte("test")
	sig := fullSign(t, keyShares, []int{1, 2, 3}, msg)

	// Flip a bit in R.
	corrupted := &Signature{R: make([]byte, 32), Z: sig.Z}
	copy(corrupted.R, sig.R)
	corrupted.R[0] ^= 0x01
	assert.False(t, Verify(keyShares[1].PublicKey, msg, corrupted))
}

func TestVerifyCorruptedZ(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	msg := []byte("test")
	sig := fullSign(t, keyShares, []int{1, 2, 3}, msg)

	// Flip a bit in Z.
	corrupted := &Signature{R: sig.R, Z: make([]byte, 32)}
	copy(corrupted.Z, sig.Z)
	corrupted.Z[0] ^= 0x01
	assert.False(t, Verify(keyShares[1].PublicKey, msg, corrupted))
}

func TestVerifyNonCanonicalPoint(t *testing.T) {
	t.Parallel()
	// R with all 0xff is not a valid Edwards point.
	badR := make([]byte, 32)
	for i := range badR {
		badR[i] = 0xff
	}
	sig := &Signature{R: badR, Z: make([]byte, 32)}
	assert.False(t, Verify(make([]byte, 32), []byte("msg"), sig))
}

func TestVerifyNonCanonicalScalar(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	msg := []byte("test")
	sig := fullSign(t, keyShares, []int{1, 2, 3}, msg)

	// Z with all 0xff is not a canonical scalar (>= group order).
	badZ := make([]byte, 32)
	for i := range badZ {
		badZ[i] = 0xff
	}
	corrupted := &Signature{R: sig.R, Z: badZ}
	assert.False(t, Verify(keyShares[1].PublicKey, msg, corrupted))
}

// TestVerifyRejectsNonCanonicalEncodings: RFC 9591 Section 6.1 verification
// is RFC 8032 Section 5.1.7, whose decoding (Section 5.1.3) fails for a
// y-coordinate >= p and for x = 0 with the sign bit set; a decoding failure
// of R or of the public key makes the signature invalid.
func TestVerifyRejectsNonCanonicalEncodings(t *testing.T) {
	t.Parallel()
	msg := mustHex(t, vecMessage)
	pk := mustHex(t, vecGroupPublicKey)
	sigBytes := mustHex(t, vecSig)
	require.True(t, VerifyBytes(pk, msg, sigBytes), "Appendix E.1 signature verifies")

	for name, enc := range map[string]string{
		"y = p+1": encNonCanonicalYPlus1, "y = p": encNonCanonicalYEqP, "x=0 sign=1": encNonCanonicalX0Sign,
	} {
		badEnc := encBytes(t, enc)
		assert.False(t, Verify(badEnc, msg, &Signature{R: sigBytes[:32], Z: sigBytes[32:]}), "%s as public key", name)
		assert.False(t, Verify(pk, msg, &Signature{R: badEnc, Z: sigBytes[32:]}), "%s as R", name)
	}
}

// TestVerifyCofactoredEquation checks that Verify evaluates the equation
// RFC 9591 Section 6.1 mandates, [8][z]B = [8]R + [8][c]PK, and not the
// cofactorless [z]B = R + [c]PK that RFC 8032 Section 5.1.7 permits as an
// alternative. The two differ only when R carries a small-order component:
// with the Appendix E.1 group secret key, a signature over R' = R + T (T of
// order 8) with c = H2(R' || PK || msg) satisfies the cofactored equation
// but not the cofactorless one. Honest signatures (prime-order R) satisfy
// both, which is why they are also accepted by crypto/ed25519.
func TestVerifyCofactoredEquation(t *testing.T) {
	t.Parallel()
	msg := []byte("cofactored verification")
	sk := mustScalar(t, vecGroupSecretKey)
	pk := mustHex(t, vecGroupPublicKey)
	require.Equal(t, pk, edwards25519.NewGeneratorPoint().ScalarBaseMult(sk).Bytes())

	r := H3([]byte("test-only nonce for the Appendix E.1 key"))
	R := edwards25519.NewGeneratorPoint().ScalarBaseMult(r)
	T := order8Point(t)
	Rprime := edwards25519.NewIdentityPoint().Add(R, T)

	// sign produces (R_enc, z) with c = H2(R_enc || PK || msg), z = r + c*sk.
	sign := func(rEnc []byte) (*Signature, *edwards25519.Scalar) {
		c := H2(concat(rEnc, pk, msg))
		z := edwards25519.NewScalar().MultiplyAdd(c, sk, r)
		return &Signature{R: rEnc, Z: z.Bytes()}, c
	}

	honest, _ := sign(R.Bytes())
	assert.True(t, Verify(pk, msg, honest))
	assert.True(t, ed25519.Verify(ed25519.PublicKey(pk), msg, honest.Bytes()))

	// [8]R' = [8]R, so the cofactored equation holds for R' and Verify
	// accepts, exactly as Section 6.1 requires...
	torsion, c := sign(Rprime.Bytes())
	assert.True(t, Verify(pk, msg, torsion))
	assert.Equal(t, 1, edwards25519.NewIdentityPoint().MultByCofactor(Rprime).Equal(edwards25519.NewIdentityPoint().MultByCofactor(R)))

	// ...while the cofactorless relation [z]B == R' + [c]PK fails by exactly T.
	z, err := edwards25519.NewScalar().SetCanonicalBytes(torsion.Z)
	require.NoError(t, err)
	lhs := edwards25519.NewGeneratorPoint().ScalarBaseMult(z)
	PK, err := decodePoint(pk)
	require.NoError(t, err)
	rhs := edwards25519.NewIdentityPoint().ScalarMult(c, PK)
	rhs.Add(rhs, Rprime)
	assert.NotEqual(t, 1, lhs.Equal(rhs), "cofactorless equation must not hold for R' = R + T")
	assert.Equal(t, 1, lhs.Equal(edwards25519.NewIdentityPoint().Subtract(rhs, T)))
}
