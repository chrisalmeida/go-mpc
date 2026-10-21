package frost

import (
	"encoding/hex"
	"testing"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Point encodings used to exercise RFC 8032 Section 5.1.3 decoding and the
// extra checks of RFC 9591 Section 6.1 DeserializeElement.
//
// p = 2^255 - 19. Encodings are little-endian y with the sign of x in the top
// bit of the last byte.
const (
	// (0, 1): the identity. Canonical.
	encIdentity = "0100000000000000000000000000000000000000000000000000000000000000"
	// (0, -1) = (0, p-1): the point of order 2. Canonical.
	encOrder2 = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
	// (±sqrt(-1), 0): the two points of order 4. Canonical.
	encOrder4a = "0000000000000000000000000000000000000000000000000000000000000000"
	encOrder4b = "0000000000000000000000000000000000000000000000000000000000000080"

	// Non-canonical encodings that RFC 8032 Section 5.1.3 must reject.
	// y = p + 1 (>= p; reduces to y = 1, the identity).
	encNonCanonicalYPlus1 = "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
	// y = p (>= p; reduces to y = 0, an order-4 point).
	encNonCanonicalYEqP = "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
	// y = 1 with the sign bit set: x = 0 and x_0 = 1.
	encNonCanonicalX0Sign = "0100000000000000000000000000000000000000000000000000000000000080"
)

func encBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// order8Point returns a point of order exactly 8, found deterministically:
// for the first valid encodings with small y, [L]P keeps only the torsion
// component of P (and [L] = [5] on it, which preserves its order).
func order8Point(t *testing.T) *edwards25519.Point {
	t.Helper()
	identity := edwards25519.NewIdentityPoint()
	lMinus1 := edwards25519.NewScalar().Subtract(edwards25519.NewScalar(), scalarFromUint64(1))
	four := scalarFromUint64(4)
	for y := byte(2); y < 255; y++ {
		var enc [32]byte
		enc[0] = y
		P, err := edwards25519.NewIdentityPoint().SetBytes(enc[:])
		if err != nil {
			continue
		}
		T := edwards25519.NewIdentityPoint().ScalarMult(lMinus1, P)
		T.Add(T, P) // [L]P
		eight := edwards25519.NewIdentityPoint().MultByCofactor(T)
		fourT := edwards25519.NewIdentityPoint().ScalarMult(four, T)
		if eight.Equal(identity) == 1 && fourT.Equal(identity) != 1 {
			return T
		}
	}
	t.Fatal("no order-8 point found")
	return nil
}

// invalidElements returns encodings that DeserializeElement (RFC 9591
// Section 6.1) must reject, with the expected error for each.
func invalidElements(t *testing.T) map[string][]byte {
	t.Helper()
	T8 := order8Point(t)
	mixed := edwards25519.NewIdentityPoint().Add(edwards25519.NewGeneratorPoint(), T8)
	return map[string][]byte{
		"identity":                 encBytes(t, encIdentity),
		"order 2":                  encBytes(t, encOrder2),
		"order 4":                  encBytes(t, encOrder4a),
		"order 4 (other sign)":     encBytes(t, encOrder4b),
		"order 8":                  T8.Bytes(),
		"B + order-8 point":        mixed.Bytes(),
		"non-canonical y = p+1":    encBytes(t, encNonCanonicalYPlus1),
		"non-canonical y = p":      encBytes(t, encNonCanonicalYEqP),
		"non-canonical x=0 sign=1": encBytes(t, encNonCanonicalX0Sign),
		"wrong length":             make([]byte, 31),
		"not on curve (y = 2)":     append([]byte{0x02}, make([]byte, 31)...),
	}
}

func TestDecodePointRFC8032(t *testing.T) {
	t.Parallel()

	// A canonical encoding of a valid point decodes to that point.
	B := edwards25519.NewGeneratorPoint()
	p, err := decodePoint(B.Bytes())
	require.NoError(t, err)
	assert.Equal(t, 1, p.Equal(B))

	// RFC 8032 decoding accepts the identity and small-order points...
	for name, enc := range map[string]string{"identity": encIdentity, "order 2": encOrder2, "order 4": encOrder4a, "order 4b": encOrder4b} {
		p, err := decodePoint(encBytes(t, enc))
		require.NoError(t, err, name)
		assert.Equal(t, encBytes(t, enc), p.Bytes(), "%s re-encodes identically", name)
	}
	T8 := order8Point(t)
	_, err = decodePoint(T8.Bytes())
	require.NoError(t, err, "order 8")

	// ...but rejects non-canonical encodings (y >= p, or x = 0 with sign bit set).
	for name, enc := range map[string]string{
		"y = p+1": encNonCanonicalYPlus1, "y = p": encNonCanonicalYEqP, "x=0 sign=1": encNonCanonicalX0Sign,
	} {
		b := encBytes(t, enc)
		// The underlying library accepts these; decodePoint must not.
		_, libErr := edwards25519.NewIdentityPoint().SetBytes(b)
		require.NoError(t, libErr, "%s: SetBytes is lax by design", name)
		_, err := decodePoint(b)
		assert.ErrorIs(t, err, errElementNonCanonical, name)
	}

	_, err = decodePoint(make([]byte, 31))
	assert.ErrorIs(t, err, errElementLength)
	_, err = decodePoint(append([]byte{0x02}, make([]byte, 31)...))
	assert.Error(t, err, "y = 2 is not on the curve")
}

func TestDeserializeElementRFC9591(t *testing.T) {
	t.Parallel()

	// Prime-order, non-identity points are accepted.
	for _, k := range []uint64{1, 2, 3, 1 << 40} {
		P := edwards25519.NewGeneratorPoint().ScalarBaseMult(scalarFromUint64(k))
		got, err := deserializeElement(P.Bytes())
		require.NoError(t, err)
		assert.Equal(t, 1, got.Equal(P))
	}

	expected := map[string]error{
		"identity":                 errElementIdentity,
		"order 2":                  errElementSmallOrder,
		"order 4":                  errElementSmallOrder,
		"order 4 (other sign)":     errElementSmallOrder,
		"order 8":                  errElementSmallOrder,
		"B + order-8 point":        errElementSmallOrder,
		"non-canonical y = p+1":    errElementNonCanonical,
		"non-canonical y = p":      errElementNonCanonical,
		"non-canonical x=0 sign=1": errElementNonCanonical,
		"wrong length":             errElementLength,
	}
	for name, enc := range invalidElements(t) {
		_, err := deserializeElement(enc)
		require.Error(t, err, name)
		if want, ok := expected[name]; ok {
			assert.ErrorIs(t, err, want, name)
		}
	}

	// The mixed point is not small order itself, only outside the subgroup.
	mixed := invalidElements(t)["B + order-8 point"]
	P, err := decodePoint(mixed)
	require.NoError(t, err)
	assert.NotEqual(t, 1, edwards25519.NewIdentityPoint().MultByCofactor(P).Equal(edwards25519.NewIdentityPoint()))
}

// --- Protocol-level rejection of invalid Elements (RFC 9591 Section 5) ---

// signingSession returns fresh round 1 state and commitments for signers.
func signingSession(t *testing.T, keyShares map[int]*KeyShare, signers []int) (map[int]*SignerState, map[int]*Round1State, map[int]*NonceCommitment) {
	t.Helper()
	states := make(map[int]*SignerState)
	r1 := make(map[int]*Round1State)
	comms := make(map[int]*NonceCommitment)
	for _, id := range signers {
		states[id] = NewSignerState(keyShares[id])
		st, c, err := SignRound1(states[id], signers)
		require.NoError(t, err)
		r1[id] = st
		comms[id] = c
	}
	return states, r1, comms
}

func TestSignRound2RejectsInvalidCommitmentElements(t *testing.T) {
	t.Parallel()
	keyShares, err := buildDKG([]int{1, 2, 3}, 2)
	require.NoError(t, err)
	signers := []int{1, 2}

	for name, bad := range invalidElements(t) {
		for _, field := range []string{"hiding", "binding"} {
			t.Run(name+"/"+field, func(t *testing.T) {
				states, r1, comms := signingSession(t, keyShares, signers)
				if field == "hiding" {
					comms[2].HidingNonceCommitment = bad
				} else {
					comms[2].BindingNonceCommitment = bad
				}
				_, err := SignRound2(states[1], r1[1], &Round2Input{Message: []byte("m"), AllCommitments: comms})
				var inputErr *InvalidInputError
				require.ErrorAs(t, err, &inputErr)
				assert.False(t, r1[1].consumed, "nonces must remain unused after rejected input")
			})
		}
	}
}

func TestAggregateRejectsInvalidElements(t *testing.T) {
	t.Parallel()
	keyShares, err := buildDKG([]int{1, 2, 3}, 2)
	require.NoError(t, err)
	signers := []int{1, 2}
	msg := []byte("aggregate element validation")

	states, r1, comms := signingSession(t, keyShares, signers)
	shares := make(map[int]*SignatureShare)
	for _, id := range signers {
		sh, err := SignRound2(states[id], r1[id], &Round2Input{Message: msg, AllCommitments: comms})
		require.NoError(t, err)
		shares[id] = sh
	}
	verShares := map[int][]byte{1: keyShares[1].VerificationShare, 2: keyShares[2].VerificationShare}

	// Sanity: the untampered session aggregates.
	_, err = Aggregate(comms, shares, msg, keyShares[1].PublicKey, verShares, signers)
	require.NoError(t, err)

	for name, bad := range invalidElements(t) {
		t.Run(name, func(t *testing.T) {
			var inputErr *InvalidInputError

			_, err := Aggregate(comms, shares, msg, bad, verShares, signers)
			require.ErrorAs(t, err, &inputErr, "group public key")

			badVer := map[int][]byte{1: verShares[1], 2: bad}
			_, err = Aggregate(comms, shares, msg, keyShares[1].PublicKey, badVer, signers)
			require.ErrorAs(t, err, &inputErr, "verification share")

			badComms := map[int]*NonceCommitment{
				1: comms[1],
				2: {HidingNonceCommitment: comms[2].HidingNonceCommitment, BindingNonceCommitment: bad},
			}
			_, err = Aggregate(badComms, shares, msg, keyShares[1].PublicKey, verShares, signers)
			require.ErrorAs(t, err, &inputErr, "binding nonce commitment")
			_, err = Aggregate(badComms, shares, msg, keyShares[1].PublicKey, nil, signers)
			require.ErrorAs(t, err, &inputErr, "binding nonce commitment, no share verification")
		})
	}
}

func TestDKGRejectsInvalidElements(t *testing.T) {
	t.Parallel()
	s := runDKGRound1(t, []int{1, 2, 3}, 2)
	runDKGRound2(t, s)

	for name, bad := range invalidElements(t) {
		for _, field := range []string{"phi0", "phi1", "proofR"} {
			t.Run(name+"/"+field, func(t *testing.T) {
				tampered := roundTrip(t, "DKGRound1Output", s.r1[2])
				switch field {
				case "phi0":
					tampered.FeldmanCommitments[0] = bad
				case "phi1":
					tampered.FeldmanCommitments[1] = bad
				case "proofR":
					tampered.ProofR = bad
				}
				r1 := map[int]*DKGRound1Output{1: s.r1[1], 2: tampered, 3: s.r1[3]}
				_, err := DKGRound2(s.configs[1], s.coeffs[1], r1)
				requireCheating(t, err, 2)
				_, err = DKGFinalize(s.configs[1], s.coeffs[1], r1, s.r2)
				requireCheating(t, err, 2)
			})
		}
	}
}

func TestRefreshRejectsInvalidElements(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	states := makeSignerStates(keyShares)
	allIDs := []int{1, 2, 3}

	for name, bad := range invalidElements(t) {
		t.Run(name, func(t *testing.T) {
			allR1 := make(map[int]*RefreshRound1Output)
			allCoeffs := make(map[int][]*edwards25519.Scalar)
			allSeeds := make(map[int][16]byte)
			for _, id := range allIDs {
				r1, coeffs, seed, err := RefreshRound1(states[id])
				require.NoError(t, err)
				allR1[id] = r1
				allCoeffs[id] = coeffs
				allSeeds[id] = seed
			}
			allR2 := make(map[int]*RefreshRound2Output)
			for _, id := range allIDs {
				r2, err := RefreshRound2(states[id], allCoeffs[id], allSeeds[id])
				require.NoError(t, err)
				allR2[id] = r2
			}
			allR1[2].FeldmanCommitments[0] = bad
			err := RefreshFinalize(states[1], allCoeffs[1], allSeeds[1], allR1, allR2)
			requireCheating(t, err, 2)
		})
	}
}
