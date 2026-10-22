package frost

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/require"
)

func TestSignRound1RejectsInvalidKeyBeforeOutput(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		change func(*SignerState)
	}{
		{"missing share", func(s *SignerState) { s.KeyShare = nil }},
		{"short scalar", func(s *SignerState) { s.KeyShare.SecretShare = make([]byte, 31) }},
		{"noncanonical scalar", func(s *SignerState) {
			s.KeyShare.SecretShare = encBytes(t, "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
		}},
		{"inconsistent verification share", func(s *SignerState) { s.KeyShare.VerificationShare = edwards25519.NewGeneratorPoint().Bytes() }},
		{"short coefficient vector", func(s *SignerState) { s.KeyShare.GroupCommitments = s.KeyShare.GroupCommitments[:1] }},
		{"wrong constant commitment", func(s *SignerState) { s.KeyShare.GroupCommitments[0] = edwards25519.NewGeneratorPoint().Bytes() }},
		{"duplicate configured ID", func(s *SignerState) { s.KeyShare.AllIDs = []int{1, 2, 2, 3} }},
		{"zero threshold", func(s *SignerState) { s.KeyShare.Threshold = 0 }},
		{"negative epoch", func(s *SignerState) { s.Epoch = -1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			signer := NewSignerState(fullSetup(t)[1])
			tc.change(signer)
			before, err := MarshalSignerState(signer)
			require.NoError(t, err)
			require.NotPanics(t, func() {
				state, commitment, err := SignRound1(signer, []int{1, 2, 3})
				var corrupt *CorruptStateError
				require.ErrorAs(t, err, &corrupt)
				require.Nil(t, state)
				require.Nil(t, commitment)
			})
			after, err := MarshalSignerState(signer)
			require.NoError(t, err)
			require.Equal(t, before, after)
		})
	}
}

func TestSignRound1RejectsInvalidConfiguredElements(t *testing.T) {
	t.Parallel()
	for name, encoded := range invalidElements(t) {
		for _, field := range []string{"public key", "verification share", "coefficient"} {
			t.Run(field+"/"+name, func(t *testing.T) {
				t.Parallel()
				signer := NewSignerState(fullSetup(t)[1])
				switch field {
				case "public key":
					signer.KeyShare.PublicKey = encoded
				case "verification share":
					signer.KeyShare.VerificationShare = encoded
				case "coefficient":
					if name == "identity" {
						// Aggregation may cancel a nonconstant DKG coefficient.
						return
					}
					signer.KeyShare.GroupCommitments[1] = encoded
				}
				state, commitment, err := SignRound1(signer, []int{1, 2, 3})
				var corrupt *CorruptStateError
				require.ErrorAs(t, err, &corrupt)
				require.Nil(t, state)
				require.Nil(t, commitment)
			})
		}
	}
}

func TestSignRound1RejectsUnconfiguredParticipant(t *testing.T) {
	t.Parallel()
	signer := NewSignerState(fullSetup(t)[1])
	state, commitment, err := SignRound1(signer, []int{1, 2, 4})
	var input *InvalidInputError
	require.ErrorAs(t, err, &input)
	require.Nil(t, state)
	require.Nil(t, commitment)
}

func TestSignRound1RejectsMissingSigner(t *testing.T) {
	t.Parallel()
	require.NotPanics(t, func() {
		state, commitment, err := SignRound1(nil, []int{1})
		require.Error(t, err)
		require.Nil(t, state)
		require.Nil(t, commitment)
	})
}

func TestSigningRejectsMalformedRestoredKey(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		field string
		value json.RawMessage
	}{
		{"secret_share", json.RawMessage(`"edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"`)},
		{"public_key", json.RawMessage(`"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"`)},
		{"verification_share", json.RawMessage(`"0100000000000000000000000000000000000000000000000000000000000000"`)},
		{"threshold", json.RawMessage(`0`)},
		{"all_ids", json.RawMessage(`[1,2,2,3]`)},
	} {
		t.Run(tc.field, func(t *testing.T) {
			t.Parallel()
			encoded, err := MarshalKeyShare(fullSetup(t)[1])
			require.NoError(t, err)
			var fields map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(encoded, &fields))
			fields[tc.field] = tc.value
			encoded, err = json.Marshal(fields)
			require.NoError(t, err)
			restored, err := UnmarshalKeyShare(encoded)
			require.NoError(t, err)
			state, output, err := SignRound1(NewSignerState(restored), []int{1, 2, 3})
			require.Error(t, err)
			require.Nil(t, state)
			require.Nil(t, output)
		})
	}
}

func TestSigningAcceptsMinimalKeyConfiguration(t *testing.T) {
	t.Parallel()
	keys := fullSetup(t)
	// RFC 9591 signing needs the local secret, group key, IDs and threshold.
	// Neither the original DKG polynomial nor a stored verification share is
	// required to produce a share; Aggregate may receive those shares separately.
	verification := make(map[int][]byte)
	for id, key := range keys {
		verification[id] = append([]byte(nil), key.VerificationShare...)
		key.VerificationShare = nil
		key.GroupCommitments = nil
	}
	signers := []int{1, 2, 3}
	states, round1, commitments := signingSession(t, keys, signers)
	message := []byte("minimal RFC signing configuration")
	shares := make(map[int]*SignatureShare)
	for _, id := range signers {
		share, err := SignRound2(states[id], round1[id], &Round2Input{Message: message, AllCommitments: commitments})
		require.NoError(t, err)
		shares[id] = share
	}
	signature, err := Aggregate(commitments, shares, message, keys[1].PublicKey, verification, signers)
	require.NoError(t, err)
	require.True(t, ed25519.Verify(keys[1].PublicKey, message, signature.Bytes()))
}

func TestKeyValidationAcceptsRefreshedShareWithOriginalCommitments(t *testing.T) {
	t.Parallel()
	states := makeSignerStates(fullSetup(t))
	before := append([]byte(nil), states[1].KeyShare.SecretShare...)
	commitments := make([][]byte, len(states[1].KeyShare.GroupCommitments))
	for i, commitment := range states[1].KeyShare.GroupCommitments {
		commitments[i] = append([]byte(nil), commitment...)
	}
	runRefresh(t, states)
	require.NotEqual(t, before, states[1].KeyShare.SecretShare)
	require.Equal(t, commitments, states[1].KeyShare.GroupCommitments)
	for _, state := range states {
		require.NoError(t, validateSignerState(state, "test"))
	}
	message := []byte("refreshed shares retain original DKG metadata")
	signature := fullSignWithStates(t, states, []int{1, 2, 3}, message)
	require.True(t, ed25519.Verify(states[1].KeyShare.PublicKey, message, signature.Bytes()))
}

func TestKeyValidationAllowsZeroShareAndCancelledCoefficient(t *testing.T) {
	t.Parallel()
	key := fullSetup(t)[1]
	key.SecretShare = edwards25519.NewScalar().Bytes()
	key.VerificationShare = edwards25519.NewIdentityPoint().Bytes()
	key.GroupCommitments[1] = edwards25519.NewIdentityPoint().Bytes()
	require.NoError(t, validateKeyShare(key, "test"))
}

func TestSignRound2RejectsInconsistentRestoredKey(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		change func(*KeyShare)
	}{
		{"changed secret", func(k *KeyShare) { k.SecretShare = scalarFromUint64(42).Bytes() }},
		{"changed configured group", func(k *KeyShare) { k.AllIDs = []int{1, 2, 4} }},
		{"invalid threshold", func(k *KeyShare) { k.Threshold = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			signers, states, commitments := sessionFixture(t)
			original := *signers[1].KeyShare
			tc.change(signers[1].KeyShare)
			message := []byte("local key rejection preserves the nonce pair")
			share, err := SignRound2(signers[1], states[1], &Round2Input{Message: message, AllCommitments: commitments})
			require.Error(t, err)
			require.Nil(t, share)
			require.False(t, states[1].consumed)
			require.False(t, states[1].use.consumed)
			*signers[1].KeyShare = original
			finishNonceSession(t, signers, states, commitments, message)
		})
	}
}

func TestRefreshRejectsInvalidKeyBeforeOutputOrMutation(t *testing.T) {
	t.Parallel()
	for _, phase := range []string{"round 1", "round 2", "finalize"} {
		t.Run(phase, func(t *testing.T) {
			t.Parallel()
			signer := NewSignerState(fullSetup(t)[1])
			_, coeffs, seed, err := RefreshRound1(signer)
			require.NoError(t, err)
			signer.KeyShare.SecretShare = scalarFromUint64(42).Bytes()
			before, err := MarshalSignerState(signer)
			require.NoError(t, err)
			switch phase {
			case "round 1":
				out, private, _, err := RefreshRound1(signer)
				require.Error(t, err)
				require.Nil(t, out)
				require.Nil(t, private)
			case "round 2":
				out, err := RefreshRound2(signer, coeffs, seed)
				require.Error(t, err)
				require.Nil(t, out)
			case "finalize":
				err := RefreshFinalize(signer, coeffs, seed, nil, nil)
				var corrupt *CorruptStateError
				require.ErrorAs(t, err, &corrupt)
			}
			after, err := MarshalSignerState(signer)
			require.NoError(t, err)
			require.Equal(t, before, after)
		})
	}
}

func TestRefreshRound2RejectsWrongLocalPolynomialSize(t *testing.T) {
	t.Parallel()
	signer := NewSignerState(fullSetup(t)[1])
	_, coeffs, seed, err := RefreshRound1(signer)
	require.NoError(t, err)
	for _, bad := range [][]*edwards25519.Scalar{nil, coeffs[:len(coeffs)-1], append(append([]*edwards25519.Scalar(nil), coeffs...), edwards25519.NewScalar())} {
		out, err := RefreshRound2(signer, bad, seed)
		var corrupt *CorruptStateError
		require.ErrorAs(t, err, &corrupt)
		require.Nil(t, out)
		require.ErrorAs(t, RefreshFinalize(signer, bad, seed, nil, nil), &corrupt)
	}
	coeffs[0] = nil
	out, err := RefreshRound2(signer, coeffs, seed)
	var corrupt *CorruptStateError
	require.ErrorAs(t, err, &corrupt)
	require.Nil(t, out)
	require.ErrorAs(t, RefreshFinalize(signer, coeffs, seed, nil, nil), &corrupt)
}

func TestRefreshRejectsMissingSigner(t *testing.T) {
	t.Parallel()
	for _, signer := range []*SignerState{nil, NewSignerState(nil)} {
		out1, coeffs, _, err := RefreshRound1(signer)
		require.Error(t, err)
		require.Nil(t, out1)
		require.Nil(t, coeffs)
		out2, err := RefreshRound2(signer, nil, [16]byte{})
		require.Error(t, err)
		require.Nil(t, out2)
		require.Error(t, RefreshFinalize(signer, nil, [16]byte{}, nil, nil))
	}
}
