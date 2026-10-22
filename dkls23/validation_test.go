package dkls23

import (
	"encoding/json"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

func TestSignRound1RejectsInvalidSetupBeforeOutput(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		change func(*SignerSetup)
	}{
		{"missing Alice material", func(s *SignerSetup) { delete(s.AliceBaseOT, 2) }},
		{"missing Bob material", func(s *SignerSetup) { delete(s.BobBaseOT, 2) }},
		{"missing FZero material", func(s *SignerSetup) { delete(s.FZeroSeeds, 2) }},
		{"short receiver vector", func(s *SignerSetup) { s.AliceBaseOT[2].Seeds = s.AliceBaseOT[2].Seeds[:LambdaC-1] }},
		{"short choice vector", func(s *SignerSetup) { s.AliceBaseOT[2].Sigma = s.AliceBaseOT[2].Sigma[:LambdaC-1] }},
		{"short receiver seed", func(s *SignerSetup) { s.AliceBaseOT[2].Seeds[0] = make([]byte, 31) }},
		{"short sender vector", func(s *SignerSetup) { s.BobBaseOT[2].Seeds1 = s.BobBaseOT[2].Seeds1[:LambdaC-1] }},
		{"short sender seed", func(s *SignerSetup) { s.BobBaseOT[2].Seeds0[0] = make([]byte, 31) }},
		{"invalid public key", func(s *SignerSetup) { s.PubKey = make([]byte, 33) }},
		{"negative epoch", func(s *SignerSetup) { s.Epoch = -1 }},
		{"duplicate configured ID", func(s *SignerSetup) { s.AllIDs = []int{1, 2, 2, 3} }},
		{"zero threshold", func(s *SignerSetup) { s.Threshold = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			setup := fullSetup(t)[1]
			tc.change(setup)
			before, err := MarshalSetup(setup)
			require.NoError(t, err)
			state, messages, err := SignRound1(setup, t.Name(), []int{1, 2, 3})
			var corrupt *CorruptStateError
			require.ErrorAs(t, err, &corrupt)
			require.Nil(t, state)
			require.Nil(t, messages)
			after, err := MarshalSetup(setup)
			require.NoError(t, err)
			require.Equal(t, before, after, "rejection must not spend the session or change setup")
		})
	}
}

func TestSignRound1RejectsUnconfiguredParticipant(t *testing.T) {
	t.Parallel()
	setup := fullSetup(t)[1]
	// Even complete seed entries cannot authorize a party outside AllIDs.
	setup.AliceBaseOT[4] = setup.AliceBaseOT[3]
	setup.BobBaseOT[4] = setup.BobBaseOT[3]
	setup.FZeroSeeds[4] = setup.FZeroSeeds[3]
	state, messages, err := SignRound1(setup, t.Name(), []int{1, 2, 4})
	var input *InvalidInputError
	require.ErrorAs(t, err, &input)
	require.Nil(t, state)
	require.Nil(t, messages)
	require.Zero(t, setup.SessionIDs[t.Name()])
}

func TestSignRound1RejectsMissingSetup(t *testing.T) {
	t.Parallel()
	require.NotPanics(t, func() {
		state, messages, err := SignRound1(nil, t.Name(), []int{1})
		require.Error(t, err)
		require.Nil(t, state)
		require.Nil(t, messages)
	})
}

func TestSigningRejectsMalformedRestoredSetup(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		field string
		value json.RawMessage
	}{
		{"pub_key", json.RawMessage(`"000000000000000000000000000000000000000000000000000000000000000000"`)},
		{"epoch", json.RawMessage(`-1`)},
		{"threshold", json.RawMessage(`0`)},
		{"all_ids", json.RawMessage(`[1,2,2,3]`)},
	} {
		t.Run(tc.field, func(t *testing.T) {
			t.Parallel()
			encoded, err := MarshalSetup(fullSetup(t)[1])
			require.NoError(t, err)
			var fields map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(encoded, &fields))
			fields[tc.field] = tc.value
			encoded, err = json.Marshal(fields)
			require.NoError(t, err)
			// The legacy decoder is retained; protocol activation supplies the
			// local checks even for documents that it still accepts.
			restored, err := UnmarshalSetup(encoded)
			require.NoError(t, err)
			state, output, err := SignRound1(restored, t.Name(), []int{1, 2, 3})
			require.Error(t, err)
			require.Nil(t, state)
			require.Nil(t, output)
			require.Empty(t, restored.SessionIDs)
		})
	}
}

func TestSigningAcceptsPairwiseSetupForSelectedSubset(t *testing.T) {
	t.Parallel()
	setups := setupSigners(t, []int{1, 2, 3}, 2)
	for _, id := range []int{1, 2} {
		delete(setups[id].AliceBaseOT, 3)
		delete(setups[id].BobBaseOT, 3)
		delete(setups[id].FZeroSeeds, 3)
		require.NoError(t, validateSetupState(setups[id], "test"))
		// The same partial setup remains usable after serialization.
		encoded, err := MarshalSetup(setups[id])
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(encoded, setups[id]))
	}
	message := []byte("pairwise setup only for the selected quorum")
	r, signature := runSigning(t, setups, []int{1, 2}, message)
	verifyECDSA(t, setups[1].PubKey, message, r, signature)
}

func TestSetupValidationAcceptsRefreshedSigningMaterial(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	runRefresh(t, setups)
	for _, setup := range setups {
		require.NoError(t, validateSetupState(setup, "test"))
	}
	message := []byte("validate and sign after refresh")
	r, signature := runSigning(t, setups, []int{1, 2, 3}, message)
	verifyECDSA(t, setups[1].PubKey, message, r, signature)
}

func TestSignRound2RejectsInconsistentPrivateState(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		change func(*Round1State)
	}{
		{"nonce changed to zero", func(s *Round1State) { s.R_i.Zero() }},
		{"wrong nonce point", func(s *Round1State) { s.R_iPoint = fullSetup(t)[1].PubKey }},
		{"invalid nonce point", func(s *Round1State) { s.R_iPoint = make([]byte, 33) }},
		{"wrong commitment", func(s *Round1State) { s.Com[0] ^= 1 }},
		{"wrong salt", func(s *Round1State) { s.Salt[0] ^= 1 }},
		{"wrong zero sharing", func(s *Round1State) { s.ZetaI.Add(new(btcec.ModNScalar).SetInt(1)) }},
		{"wrong VOLE scalar", func(s *Round1State) { s.VoleBobForRound2[2].Chi.Add(new(btcec.ModNScalar).SetInt(1)) }},
		{"short VOLE vector", func(s *Round1State) { s.VoleBobForRound2[2].Gamma = s.VoleBobForRound2[2].Gamma[:Xi-1] }},
		{"missing VOLE peer", func(s *Round1State) { delete(s.VoleBobForRound2, 2) }},
		{"extra VOLE peer", func(s *Round1State) { s.VoleBobForRound2[4] = s.VoleBobForRound2[2] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			setups := fullSetup(t)
			session := runRound1(t, setups, t.Name(), []int{1, 2, 3})
			state := session.r1States[1]
			original, err := json.Marshal(state)
			require.NoError(t, err)
			tc.change(state)
			corrupted, err := json.Marshal(state)
			require.NoError(t, err)
			before, err := MarshalSetup(setups[1])
			require.NoError(t, err)
			out, messages, err := SignRound2(setups[1], state, session.round1For(1))
			var corrupt *CorruptStateError
			require.ErrorAs(t, err, &corrupt)
			require.Nil(t, out)
			require.Nil(t, messages)
			after, err := MarshalSetup(setups[1])
			require.NoError(t, err)
			require.Equal(t, before, after, "corrupt local state must not spend the round or blame a peer")
			observed, err := json.Marshal(state)
			require.NoError(t, err)
			require.Equal(t, corrupted, observed)

			require.NoError(t, json.Unmarshal(original, state))
			runRound2(t, setups, session)
			message := []byte("valid restored round 1 still resumes")
			runRound3(t, setups, session, message)
			r, signature := session.combine(t, setups, message)
			verifyECDSA(t, setups[1].PubKey, message, r, signature)
		})
	}
}

func TestSignRound3RejectsIncompletePrivateState(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		change func(*Round2State)
	}{
		{"wrong masked share", func(s *Round2State) { s.SK_i.Add(new(btcec.ModNScalar).SetInt(1)) }},
		{"missing nonce output", func(s *Round2State) { delete(s.C_u, 2) }},
		{"missing key output", func(s *Round2State) { delete(s.C_v, 2) }},
		{"missing peer commitment", func(s *Round2State) { delete(s.Round1Commits, 2) }},
		{"extra nonce output", func(s *Round2State) { s.C_u[4] = s.C_u[2] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			setups := fullSetup(t)
			session := runRound1(t, setups, t.Name(), []int{1, 2, 3})
			runRound2(t, setups, session)
			state := session.r2States[1]
			original, err := json.Marshal(state)
			require.NoError(t, err)
			tc.change(state)
			corrupted, err := json.Marshal(state)
			require.NoError(t, err)
			before, err := MarshalSetup(setups[1])
			require.NoError(t, err)
			message := []byte("valid restored round 2 still resumes")
			out, err := SignRound3(setups[1], state, message, session.round2For(1))
			var corrupt *CorruptStateError
			require.ErrorAs(t, err, &corrupt)
			require.Nil(t, out)
			after, err := MarshalSetup(setups[1])
			require.NoError(t, err)
			require.Equal(t, before, after)
			observed, err := json.Marshal(state)
			require.NoError(t, err)
			require.Equal(t, corrupted, observed)
			require.NoError(t, json.Unmarshal(original, state))
			runRound3(t, setups, session, message)
			r, signature := session.combine(t, setups, message)
			verifyECDSA(t, setups[1].PubKey, message, r, signature)
		})
	}
}

func TestSigningAllowsZeroInversionMask(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	session := runRound1(t, setups, t.Name(), []int{1, 2, 3})
	// Protocol 3.6 step 5 samples phi_i from Zq, which includes zero. Bob's
	// round-1 correlation is sampled independently of this inversion mask.
	session.r1States[1].Phi_i.Zero()
	runRound2(t, setups, session)
	message := []byte("zero is a valid local inversion-mask share")
	runRound3(t, setups, session, message)
	r, signature := session.combine(t, setups, message)
	verifyECDSA(t, setups[1].PubKey, message, r, signature)
}

func TestRefreshRejectsInvalidSetupBeforeOutputOrMutation(t *testing.T) {
	t.Parallel()
	for _, phase := range []string{"round 1", "round 2", "finalize"} {
		t.Run(phase, func(t *testing.T) {
			t.Parallel()
			setup := fullSetup(t)[1]
			_, coeffs, seed, err := RefreshRound1(setup)
			require.NoError(t, err)
			setup.Epoch = -1
			before, err := MarshalSetup(setup)
			require.NoError(t, err)
			switch phase {
			case "round 1":
				out, private, _, err := RefreshRound1(setup)
				require.Error(t, err)
				require.Nil(t, out)
				require.Nil(t, private)
			case "round 2":
				out, err := RefreshRound2(setup, coeffs, seed)
				require.Error(t, err)
				require.Nil(t, out)
			case "finalize":
				err := RefreshFinalize(setup, coeffs, seed, nil, nil)
				var corrupt *CorruptStateError
				require.ErrorAs(t, err, &corrupt)
			}
			after, err := MarshalSetup(setup)
			require.NoError(t, err)
			require.Equal(t, before, after)
		})
	}
}

func TestRefreshRound2RejectsWrongLocalPolynomialSize(t *testing.T) {
	t.Parallel()
	setup := fullSetup(t)[1]
	_, coeffs, seed, err := RefreshRound1(setup)
	require.NoError(t, err)
	for _, bad := range [][]btcec.ModNScalar{nil, coeffs[:len(coeffs)-1], append(append([]btcec.ModNScalar(nil), coeffs...), btcec.ModNScalar{})} {
		out, err := RefreshRound2(setup, bad, seed)
		var corrupt *CorruptStateError
		require.ErrorAs(t, err, &corrupt)
		require.Nil(t, out)
		require.ErrorAs(t, RefreshFinalize(setup, bad, seed, nil, nil), &corrupt)
	}
}

func TestRefreshRejectsMissingSetup(t *testing.T) {
	t.Parallel()
	out1, coeffs, _, err := RefreshRound1(nil)
	require.Error(t, err)
	require.Nil(t, out1)
	require.Nil(t, coeffs)
	out2, err := RefreshRound2(nil, nil, [16]byte{})
	require.Error(t, err)
	require.Nil(t, out2)
	require.Error(t, RefreshFinalize(nil, nil, [16]byte{}, nil, nil))
}
