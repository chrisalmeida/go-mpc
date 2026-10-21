package frost

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RFC 9591 Appendix E.1 test vectors for FROST(Ed25519, SHA-512).
//
// MAX_PARTICIPANTS: 3, MIN_PARTICIPANTS: 2, NUM_PARTICIPANTS: 2,
// participant_list: 1,3. All hex strings are copied verbatim from the RFC
// (line-wrapped values joined).
const (
	vecGroupSecretKey = "7b1c33d3f5291d85de664833beb1ad469f7fb6025a0ec78b3a790c6e13a98304"
	vecGroupPublicKey = "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673"
	vecMessage        = "74657374"
	// share_polynomial_coefficients[1]
	vecCoefficient1 = "178199860edd8c62f5212ee91eff1295d0d670ab4ed4506866bae57e7030b204"

	vecP1ParticipantShare = "929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509"
	vecP2ParticipantShare = "a91e66e012e4364ac9aaa405fcafd370402d9859f7b6685c07eed76bf409e80d"
	vecP3ParticipantShare = "d3cb090a075eb154e82fdb4b3cb507f110040905468bb9c46da8bdea643a9a02"

	vecSig = "36282629c383bb820a88b71cae937d41f2f2adfcc3d02e55507e2fb9e2dd3cbebd9d2b0844e49ae0f3fa935161e1419aab7b47d21a37ebeae1f17d4987b3160b"
)

// vectorSigner holds the per-signer values of Appendix E.1 for P1 and P3.
type vectorSigner struct {
	id                     int
	participantShare       string
	hidingNonceRandomness  string
	bindingNonceRandomness string
	hidingNonce            string
	bindingNonce           string
	hidingNonceCommitment  string
	bindingNonceCommitment string
	bindingFactorInput     string
	bindingFactor          string
	sigShare               string
}

var vectorSigners = []vectorSigner{
	{
		id:                     1,
		participantShare:       vecP1ParticipantShare,
		hidingNonceRandomness:  "0fd2e39e111cdc266f6c0f4d0fd45c947761f1f5d3cb583dfcb9bbaf8d4c9fec",
		bindingNonceRandomness: "69cd85f631d5f7f2721ed5e40519b1366f340a87c2f6856363dbdcda348a7501",
		hidingNonce:            "812d6104142944d5a55924de6d49940956206909f2acaeedecda2b726e630407",
		bindingNonce:           "b1110165fc2334149750b28dd813a39244f315cff14d4e89e6142f262ed83301",
		hidingNonceCommitment:  "b5aa8ab305882a6fc69cbee9327e5a45e54c08af61ae77cb8207be3d2ce13de3",
		bindingNonceCommitment: "67e98ab55aa310c3120418e5050c9cf76cf387cb20ac9e4b6fdb6f82a469f932",
		bindingFactorInput: "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673" +
			"504df914fa965023fb75c25ded4bb260f417de6d32e5c442c6ba313791cc9a4948d6273e8d3511f93348ea7a708a9b862bc73ba2a79cfdfe07729a193751cbc9" +
			"73af46d8ac3440e518d4ce440a0e7d4ad5f62ca8940f32de6d8dc00fc12c660b817d587d82f856d277ce6473cae6d2f5763f7da2e8b4d799a3f3e725d4522ec7" +
			"0100000000000000000000000000000000000000000000000000000000000000",
		bindingFactor: "f2cb9d7dd9beff688da6fcc83fa89046b3479417f47f55600b106760eb3b5603",
		sigShare:      "001719ab5a53ee1a12095cd088fd149702c0720ce5fd2f29dbecf24b7281b603",
	},
	{
		id:                     3,
		participantShare:       vecP3ParticipantShare,
		hidingNonceRandomness:  "86d64a260059e495d0fb4fcc17ea3da7452391baa494d4b00321098ed2a0062f",
		bindingNonceRandomness: "13e6b25afb2eba51716a9a7d44130c0dbae0004a9ef8d7b5550c8a0e07c61775",
		hidingNonce:            "c256de65476204095ebdc01bd11dc10e57b36bc96284595b8215222374f99c0e",
		bindingNonce:           "243d71944d929063bc51205714ae3c2218bd3451d0214dfb5aeec2a90c35180d",
		hidingNonceCommitment:  "cfbdb165bd8aad6eb79deb8d287bcc0ab6658ae57fdcc98ed12c0669e90aec91",
		bindingNonceCommitment: "7487bc41a6e712eea2f2af24681b58b1cf1da278ea11fe4e8b78398965f13552",
		bindingFactorInput: "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673" +
			"504df914fa965023fb75c25ded4bb260f417de6d32e5c442c6ba313791cc9a4948d6273e8d3511f93348ea7a708a9b862bc73ba2a79cfdfe07729a193751cbc9" +
			"73af46d8ac3440e518d4ce440a0e7d4ad5f62ca8940f32de6d8dc00fc12c660b817d587d82f856d277ce6473cae6d2f5763f7da2e8b4d799a3f3e725d4522ec7" +
			"0300000000000000000000000000000000000000000000000000000000000000",
		bindingFactor: "b087686bf35a13f3dc78e780a34b0fe8a77fef1b9938c563f5573d71d8d7890f",
		sigShare:      "bd86125de990acc5e1f13781d8e32c03a9bbd4c53539bbc106058bfd14326007",
	},
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func mustScalar(t *testing.T, s string) *edwards25519.Scalar {
	t.Helper()
	sc, err := edwards25519.NewScalar().SetCanonicalBytes(mustHex(t, s))
	require.NoError(t, err)
	return sc
}

// concat returns a fresh slice holding parts joined in order.
func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// TestRFC9591VectorsEd25519 runs the Appendix E.1 vectors through this
// implementation: nonce derivation (Section 4.1), nonce commitments
// (Section 5.1), binding factor inputs and binding factors (Section 4.4),
// signature shares (Section 5.2), aggregation (Section 5.3), and
// verification (Section 6.1 plus crypto/ed25519).
func TestRFC9591VectorsEd25519(t *testing.T) {
	t.Parallel()

	msg := mustHex(t, vecMessage)
	groupPK := mustHex(t, vecGroupPublicKey)
	allIDs := []int{1, 2, 3}
	signers := []int{1, 3}

	// --- Group input parameters: check the dealer's values against our
	// polynomial and Lagrange arithmetic before using them. ---
	groupSK := mustScalar(t, vecGroupSecretKey)
	coeff1 := mustScalar(t, vecCoefficient1)
	require.Equal(t, groupPK, edwards25519.NewGeneratorPoint().ScalarBaseMult(groupSK).Bytes(),
		"group_public_key == group_secret_key * B")

	shares := map[int]string{1: vecP1ParticipantShare, 2: vecP2ParticipantShare, 3: vecP3ParticipantShare}
	for id, share := range shares {
		assert.Equal(t, mustHex(t, share), evalPoly([]*edwards25519.Scalar{groupSK, coeff1}, id).Bytes(),
			"participant_share P%d == f(%d)", id, id)
	}
	reconstructed := edwards25519.NewScalar()
	for _, id := range signers {
		term := edwards25519.NewScalar().Multiply(mustScalar(t, shares[id]), lagrangeCoeff(id, signers))
		reconstructed.Add(reconstructed, term)
	}
	assert.Equal(t, groupSK.Bytes(), reconstructed.Bytes(), "Lagrange interpolation of shares 1,3 recovers group_secret_key")

	// GroupCommitments are the Feldman commitments [A_0, A_1] = [PK, coeff1 * B].
	groupCommitments := [][]byte{groupPK, edwards25519.NewGeneratorPoint().ScalarBaseMult(coeff1).Bytes()}
	commitmentPoints, err := parseFeldmanCommitments(groupCommitments)
	require.NoError(t, err)

	// --- Signer input parameters: build the KeyShares directly. ---
	keyShares := make(map[int]*KeyShare)
	verificationShares := make(map[int][]byte)
	for _, v := range vectorSigners {
		sk := mustScalar(t, v.participantShare)
		require.NoError(t, feldmanVerify(sk, v.id, commitmentPoints), "P%d share consistent with Feldman commitments", v.id)
		pkI := edwards25519.NewGeneratorPoint().ScalarBaseMult(sk).Bytes()
		keyShares[v.id] = &KeyShare{
			ID:                v.id,
			SecretShare:       mustHex(t, v.participantShare),
			PublicKey:         groupPK,
			VerificationShare: pkI,
			GroupCommitments:  groupCommitments,
			Threshold:         2,
			AllIDs:            allIDs,
		}
		verificationShares[v.id] = pkI
	}

	// --- Round one. ---
	// Round1State and the commitment list fed to the later steps are built
	// directly from the vector values, so each of (a)-(e) stands on its own: a
	// mismatch in nonce derivation or commitment cannot cascade into (c)-(e).
	round1States := make(map[int]*Round1State)
	allCommitments := make(map[int]*NonceCommitment)
	for _, v := range vectorSigners {
		share := mustHex(t, v.participantShare)
		var hidingRand, bindingRand [32]byte
		copy(hidingRand[:], mustHex(t, v.hidingNonceRandomness))
		copy(bindingRand[:], mustHex(t, v.bindingNonceRandomness))

		// (a) nonce_generate (Section 4.1): H3(randomness || SerializeScalar(secret)),
		// checked both as the bare H3 computation and through deriveNonce.
		assert.Equal(t, mustHex(t, v.hidingNonce), H3(concat(hidingRand[:], share)).Bytes(), "P%d hiding_nonce (H3)", v.id)
		assert.Equal(t, mustHex(t, v.bindingNonce), H3(concat(bindingRand[:], share)).Bytes(), "P%d binding_nonce (H3)", v.id)
		assert.Equal(t, mustHex(t, v.hidingNonce), deriveNonce(hidingRand, share).Bytes(), "P%d hiding_nonce", v.id)
		assert.Equal(t, mustHex(t, v.bindingNonce), deriveNonce(bindingRand, share).Bytes(), "P%d binding_nonce", v.id)

		// (b) commit (Section 5.1): D_i = hiding_nonce * B, E_i = binding_nonce * B,
		// computed from the vector's nonces.
		hidingNonce := mustScalar(t, v.hidingNonce)
		bindingNonce := mustScalar(t, v.bindingNonce)
		comm := commitNonces(hidingNonce, bindingNonce)
		assert.Equal(t, mustHex(t, v.hidingNonceCommitment), comm.HidingNonceCommitment, "P%d hiding_nonce_commitment", v.id)
		assert.Equal(t, mustHex(t, v.bindingNonceCommitment), comm.BindingNonceCommitment, "P%d binding_nonce_commitment", v.id)

		vecComm := &NonceCommitment{
			HidingNonceCommitment:  mustHex(t, v.hidingNonceCommitment),
			BindingNonceCommitment: mustHex(t, v.bindingNonceCommitment),
		}
		allCommitments[v.id] = vecComm
		round1States[v.id] = &Round1State{
			Signers:      signers,
			HidingNonce:  hidingNonce,
			BindingNonce: bindingNonce,
			Commitment:   vecComm,
		}
	}

	// (c) binding factor inputs and binding factors.
	inputs := bindingFactorInputs(groupPK, allCommitments, msg, signers)
	factors := computeBindingFactors(groupPK, allCommitments, msg, signers)
	for _, v := range vectorSigners {
		assert.Equal(t, mustHex(t, v.bindingFactorInput), inputs[v.id], "P%d binding_factor_input", v.id)
		assert.Equal(t, mustHex(t, v.bindingFactor), factors[v.id].Bytes(), "P%d binding_factor", v.id)
	}

	// --- Round two: (d) signature shares. ---
	allShares := make(map[int]*SignatureShare)
	input := &Round2Input{Message: msg, AllCommitments: allCommitments}
	for _, v := range vectorSigners {
		share, err := SignRound2(NewSignerState(keyShares[v.id]), round1States[v.id], input)
		require.NoError(t, err)
		assert.Equal(t, mustHex(t, v.sigShare), share.Zi, "P%d sig_share", v.id)
		allShares[v.id] = share
	}

	// --- Aggregation: (e) final signature, verified both ways. ---
	sig, err := Aggregate(allCommitments, allShares, msg, groupPK, verificationShares, signers)
	require.NoError(t, err)
	assert.Equal(t, mustHex(t, vecSig), sig.Bytes(), "sig")
	assert.True(t, Verify(groupPK, msg, sig))
	assert.True(t, VerifyBytes(groupPK, msg, mustHex(t, vecSig)))
	assert.True(t, ed25519.Verify(ed25519.PublicKey(groupPK), msg, mustHex(t, vecSig)))
}
