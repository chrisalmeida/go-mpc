package dkls23

import (
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

// =====================================================================
// DKG types
// =====================================================================

func TestEncodingDKGRound1Output(t *testing.T) {
	allIDs := []int{1, 2, 3}
	cfg := DKGPartyConfig{MyID: 1, AllIDs: allIDs, Threshold: 3}
	out, _, err := DKGRound1(cfg)
	require.NoError(t, err)

	got := roundTrip(t, "DKGRound1Output", out)
	require.Equal(t, out.FeldmanCommitment, got.FeldmanCommitment)
	require.Len(t, got.PairwiseCommitments, 2)
	for _, id := range []int{2, 3} {
		require.Equal(t, out.PairwiseCommitments[id], got.PairwiseCommitments[id])
	}
}

func TestEncodingDKGRound2Output(t *testing.T) {
	allIDs := []int{1, 2}
	cfg1 := DKGPartyConfig{MyID: 1, AllIDs: allIDs, Threshold: 2}
	cfg2 := DKGPartyConfig{MyID: 2, AllIDs: allIDs, Threshold: 2}
	_, priv1, err := DKGRound1(cfg1)
	require.NoError(t, err)
	r1of2, _, err := DKGRound1(cfg2)
	require.NoError(t, err)
	r2, err := DKGRound2(cfg1, priv1, map[int]*DKGRound1Output{2: r1of2})
	require.NoError(t, err)

	got := roundTrip(t, "DKGRound2Output", r2)
	require.Len(t, got.SecretShares, 1)
	require.Len(t, got.PairwiseSalts, 1)
	require.Equal(t, r2.FeldmanCommitments, got.FeldmanCommitments)
	require.Equal(t, r2.FeldmanSalt, got.FeldmanSalt)
	require.Equal(t, r2.SecretShares[2], got.SecretShares[2])
	require.Equal(t, r2.PairwiseSalts[2], got.PairwiseSalts[2])
}

// =====================================================================
// Base-OT seed types
// =====================================================================

func TestEncodingBaseOTSeeds(t *testing.T) {
	t.Parallel()
	alice, bob, err := runBaseOT()
	require.NoError(t, err)

	gotA := roundTrip(t, "BaseOTReceiverSeeds", alice)
	require.Equal(t, alice.Seeds, gotA.Seeds)
	require.Equal(t, alice.Sigma, gotA.Sigma)

	gotB := roundTrip(t, "BaseOTSenderSeeds", bob)
	require.Equal(t, bob.Seeds0, gotB.Seeds0)
	require.Equal(t, bob.Seeds1, gotB.Seeds1)
}

// =====================================================================
// VOLE types
// =====================================================================

func TestEncodingVOLEBobState(t *testing.T) {
	t.Parallel()
	_, bob, err := runVOLEPairwise()
	require.NoError(t, err)

	got := roundTrip(t, "VOLEBobState", bob)
	require.Equal(t, bob.Beta, got.Beta)
	require.True(t, bob.Chi.Equals(&got.Chi))
	require.Equal(t, len(bob.Gamma), len(got.Gamma))
}

func TestEncodingVOLEAliceState(t *testing.T) {
	t.Parallel()
	alice, _, err := runVOLEPairwise()
	require.NoError(t, err)

	got := roundTrip(t, "VOLEAliceState", alice)
	require.True(t, alice.C_u.Equals(&got.C_u))
	require.True(t, alice.C_v.Equals(&got.C_v))
	require.Equal(t, len(alice.Alpha0), len(got.Alpha0))
}

func TestEncodingVOLEMultiplyMsg(t *testing.T) {
	t.Parallel()
	alice, _, err := runVOLEPairwise()
	require.NoError(t, err)
	r, _ := sampleScalar()
	sk, _ := sampleScalar()
	_, _, msg, err := VOLEAliceMultiply(alice, "test-sid", &r, &sk)
	require.NoError(t, err)

	got := roundTrip(t, "VOLEMultiplyMsg", msg)
	require.Equal(t, msg.SID, got.SID)
	require.Equal(t, msg.Mu, got.Mu)
	require.Equal(t, msg.ATilde, got.ATilde)
	require.Equal(t, msg.Eta, got.Eta)
}

// =====================================================================
// Signing types
// =====================================================================

func TestEncodingRound1Msg(t *testing.T) {
	t.Parallel()
	_, bob, err := runBaseOT()
	require.NoError(t, err)
	beta, err := sampleBeta()
	require.NoError(t, err)
	ote, _, err := OTExtReceive(bob.Seeds0, bob.Seeds1, beta, []byte("round1-msg-test"))
	require.NoError(t, err)

	m := Round1Msg{OTExt: ote}
	rand.Read(m.Commitment[:])
	got := roundTrip(t, "Round1Msg", &m)
	require.Equal(t, m.Commitment, got.Commitment)
	require.NotNil(t, got.OTExt)
	require.Equal(t, m.OTExt.U, got.OTExt.U)
	require.Equal(t, m.OTExt.XBar, got.OTExt.XBar)
	require.Equal(t, m.OTExt.TBar, got.OTExt.TBar)

	// Without an OT-extension payload.
	m2 := Round1Msg{}
	rand.Read(m2.Commitment[:])
	got2 := roundTrip(t, "Round1Msg-no-ote", &m2)
	require.Nil(t, got2.OTExt)
}

func TestEncodingRound3Msg(t *testing.T) {
	m := &Round3Msg{
		W_i: make([]byte, 32),
		U_i: make([]byte, 32),
	}
	rand.Read(m.W_i)
	rand.Read(m.U_i)
	got := roundTrip(t, "Round3Msg", m)
	require.Equal(t, m.W_i, got.W_i)
	require.Equal(t, m.U_i, got.U_i)
}

func TestEncodingSigningRoundTrip(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	msg := []byte("encoding test message")
	r1States, r1Msgs, r2States, r2Msgs, r3Frags := fullSign(t, setups, msg)

	// Round1State
	for id, st := range r1States {
		got := roundTrip(t, "Round1State", st)
		require.Equal(t, st.SigID, got.SigID, "party %d", id)
		require.True(t, st.R_i.Equals(&got.R_i), "party %d R_i", id)
		require.True(t, st.Phi_i.Equals(&got.Phi_i), "party %d Phi_i", id)
		require.Equal(t, st.R_iPoint, got.R_iPoint, "party %d R_iPoint", id)
		require.Equal(t, st.Com, got.Com, "party %d Com", id)
		require.Equal(t, st.Salt, got.Salt, "party %d Salt", id)
		require.True(t, st.ZetaI.Equals(&got.ZetaI), "party %d ZetaI", id)
		require.Equal(t, len(st.VoleBobForRound2), len(got.VoleBobForRound2), "party %d VoleBobForRound2", id)
	}

	// Round1Msg
	for id, msgs := range r1Msgs {
		for peer, m := range msgs {
			got := roundTrip(t, "Round1Msg", m)
			require.Equal(t, m.Commitment, got.Commitment, "party %d->%d", id, peer)
			require.Equal(t, m.OTExt.U, got.OTExt.U, "party %d->%d OTExt", id, peer)
		}
	}

	// Round2State
	for id, st := range r2States {
		got := roundTrip(t, "Round2State", st)
		require.True(t, st.SK_i.Equals(&got.SK_i), "party %d SK_i", id)
		require.Equal(t, st.Round1State.SigID, got.Round1State.SigID, "party %d embedded SigID", id)
	}

	// Round2Msg
	for id, msgs := range r2Msgs {
		for peer, m := range msgs {
			got := roundTrip(t, "Round2Msg", m)
			require.Equal(t, m.Decommitment, got.Decommitment, "party %d->%d Decommitment", id, peer)
			require.Equal(t, m.Salt, got.Salt, "party %d->%d Salt", id, peer)
			require.Equal(t, m.GammaU, got.GammaU, "party %d->%d GammaU", id, peer)
			require.Equal(t, m.PKi, got.PKi, "party %d->%d PKi", id, peer)
		}
	}

	// Round3Msg
	for id, frags := range r3Frags {
		for peer, m := range frags {
			got := roundTrip(t, "Round3Msg", m)
			require.Equal(t, m.W_i, got.W_i, "party %d->%d W_i", id, peer)
			require.Equal(t, m.U_i, got.U_i, "party %d->%d U_i", id, peer)
		}
	}
}

// =====================================================================
// Refresh types
// =====================================================================

func TestEncodingRefreshRoundTrip(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	allIDs := []int{1, 2, 3}

	allR1 := map[int]*RefreshRound1Output{}
	allCoeffs := map[int][]btcec.ModNScalar{}
	allSeeds := map[int][16]byte{}
	for _, id := range allIDs {
		out, coeffs, seed, err := RefreshRound1(setups[id])
		require.NoError(t, err)
		allR1[id] = out
		allCoeffs[id] = coeffs
		allSeeds[id] = seed
	}

	for id, r1 := range allR1 {
		got := roundTrip(t, "RefreshRound1Output", r1)
		require.Equal(t, len(r1.FeldmanCommitments), len(got.FeldmanCommitments), "party %d", id)
		require.Equal(t, r1.SeedCommitment, got.SeedCommitment, "party %d SeedCommitment", id)
		require.Equal(t, r1.SeedSalt, got.SeedSalt, "party %d SeedSalt", id)
	}

	allR2 := map[int]*RefreshRound2Output{}
	for _, id := range allIDs {
		out, err := RefreshRound2(setups[id], allCoeffs[id], allSeeds[id])
		require.NoError(t, err)
		allR2[id] = out
	}

	for id, r2 := range allR2 {
		got := roundTrip(t, "RefreshRound2Output", r2)
		require.Equal(t, r2.Seed, got.Seed, "party %d Seed", id)
		require.Equal(t, len(r2.SecretShares), len(got.SecretShares), "party %d SecretShares", id)
	}
}

// =====================================================================
// SignerSetup
// =====================================================================

func TestEncodingSignerSetup(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	for id, s := range setups {
		got := roundTrip(t, "SignerSetup", s)
		require.Equal(t, s.MyID, got.MyID, "party %d MyID", id)
		require.Equal(t, s.AllIDs, got.AllIDs, "party %d AllIDs", id)
		require.True(t, s.Share.Equals(&got.Share), "party %d Share", id)
		require.Equal(t, s.PubKey, got.PubKey, "party %d PubKey", id)
		require.Equal(t, s.Threshold, got.Threshold, "party %d Threshold", id)
		require.Equal(t, s.Epoch, got.Epoch, "party %d Epoch", id)
		require.Equal(t, len(s.AliceBaseOT), len(got.AliceBaseOT), "party %d AliceBaseOT", id)
		require.Equal(t, len(s.BobBaseOT), len(got.BobBaseOT), "party %d BobBaseOT", id)
		for j, a := range s.AliceBaseOT {
			require.Equal(t, a.Seeds, got.AliceBaseOT[j].Seeds)
			require.Equal(t, a.Sigma, got.AliceBaseOT[j].Sigma)
		}
		for j, b := range s.BobBaseOT {
			require.Equal(t, b.Seeds0, got.BobBaseOT[j].Seeds0)
			require.Equal(t, b.Seeds1, got.BobBaseOT[j].Seeds1)
		}
		require.Equal(t, len(s.FZeroSeeds), len(got.FZeroSeeds), "party %d FZeroSeeds", id)
	}
}

func TestEncodingSignerSetupVersion(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	b, err := json.Marshal(setups[1])
	require.NoError(t, err)
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(b, &raw))
	require.JSONEq(t, "1", string(raw["version"]))
	_, hasVoleAlice := raw["vole_alice"]
	require.False(t, hasVoleAlice, "no VOLE correlation may be persisted")
	_, hasVoleBob := raw["vole_bob"]
	require.False(t, hasVoleBob, "no VOLE correlation may be persisted")
}

func TestEncodingSignerSetupWithBlacklist(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	setups[1].Blacklist[2] = true
	setups[1].Epoch = 5
	setups[1].SessionIDs = map[string]int{"a": sessionRound1Done, "b": sessionRound3Done}

	got := roundTrip(t, "SignerSetup+blacklist", setups[1])
	require.True(t, got.Blacklist[2])
	require.False(t, got.Blacklist[3])
	require.Equal(t, 5, got.Epoch)
	require.Equal(t, setups[1].SessionIDs, got.SessionIDs)

	// A setup without the field decodes with an empty, non-nil map.
	setups[1].SessionIDs = nil
	got = roundTrip(t, "SignerSetup+nil-sessions", setups[1])
	require.NotNil(t, got.SessionIDs)
	require.Empty(t, got.SessionIDs)
}

func TestEncodingSignerSetupFunctional(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)

	// Marshal and unmarshal all setups
	restored := make(map[int]*SignerSetup)
	for id, s := range setups {
		b, err := json.Marshal(s)
		require.NoError(t, err)
		var r SignerSetup
		require.NoError(t, json.Unmarshal(b, &r))
		restored[id] = &r
	}

	// Sign with restored setups — proves the base-OT state survived round-trip
	msg := []byte("sign after deserialize")
	r, s := runSigning(t, restored, []int{1, 2, 3}, msg)
	verifyECDSA(t, restored[1].PubKey, msg, r, s)
}

// =====================================================================
// Encoding helpers
// =====================================================================

func TestScalarToHexRoundTrip(t *testing.T) {
	v, err := sampleScalar()
	require.NoError(t, err)
	s := scalarToHex(&v)
	got, err := hexToScalar(s)
	require.NoError(t, err)
	require.True(t, v.Equals(&got))
}

func TestScalarToHexZero(t *testing.T) {
	var zero btcec.ModNScalar
	s := scalarToHex(&zero)
	got, err := hexToScalar(s)
	require.NoError(t, err)
	require.True(t, zero.Equals(&got))
}

func TestHexToFixed32BadLength(t *testing.T) {
	_, err := hexToFixed32("aabb")
	require.Error(t, err)
}

func TestHexToFixed16BadLength(t *testing.T) {
	_, err := hexToFixed16("aabb")
	require.Error(t, err)
}

func TestBoolArrayRoundTrip(t *testing.T) {
	var orig [Xi]bool
	buf := make([]byte, (Xi+7)/8)
	rand.Read(buf)
	for j := 0; j < Xi; j++ {
		orig[j] = (buf[j/8]>>(uint(j)%8))&1 == 1
	}
	encoded := encodeBoolArray(orig)
	decoded, err := decodeBoolArray(encoded)
	require.NoError(t, err)
	require.Equal(t, orig, decoded)
}

func TestBoolSliceRoundTrip(t *testing.T) {
	orig := randomBools(t, LambdaC)
	encoded := encodeBoolSlice(orig)
	decoded, err := decodeBoolSlice(encoded, LambdaC)
	require.NoError(t, err)
	require.Equal(t, orig, decoded)

	_, err = decodeBoolSlice(encoded, LambdaC+8)
	require.Error(t, err)
	_, err = decodeBoolSlice("!!!bad!!!", LambdaC)
	require.Error(t, err)
}

func TestDecodeSeedSliceErrors(t *testing.T) {
	_, err := decodeSeedSlice([]string{"00"})
	require.Error(t, err, "wrong count")
	short := make([]string, LambdaC)
	for i := range short {
		short[i] = "00"
	}
	_, err = decodeSeedSlice(short)
	require.Error(t, err, "wrong seed length")
	short[0] = "zz"
	_, err = decodeSeedSlice(short)
	require.Error(t, err, "bad hex")
}

func TestIntMapKeysRoundTrip(t *testing.T) {
	m := map[int]string{1: "a", 2: "b", 3: "c"}
	sm := intMapKeys(m)
	require.Equal(t, "a", sm["1"])
	require.Equal(t, "b", sm["2"])
	got, err := stringMapKeys(sm)
	require.NoError(t, err)
	require.Equal(t, m, got)
}

func TestStringMapKeysBadKey(t *testing.T) {
	sm := map[string]string{"notanint": "val"}
	_, err := stringMapKeys(sm)
	require.Error(t, err)
}

func TestVOLESliceRoundTrip(t *testing.T) {
	data := make([][Ell + Rho][32]byte, Xi)
	for j := range data {
		for i := 0; i < Ell+Rho; i++ {
			rand.Read(data[j][i][:])
		}
	}
	encoded := encodeVOLESlice(data)
	decoded, err := decodeVOLESlice(encoded)
	require.NoError(t, err)
	require.Equal(t, data, decoded)
}

func TestVOLEFixedRoundTrip(t *testing.T) {
	var data [Xi][Ell + Rho][32]byte
	for j := 0; j < Xi; j++ {
		for i := 0; i < Ell+Rho; i++ {
			rand.Read(data[j][i][:])
		}
	}
	encoded := encodeVOLEFixed(data)
	decoded, err := decodeVOLEFixed(encoded)
	require.NoError(t, err)
	require.Equal(t, data, decoded)
}

// =====================================================================
// Encoding error paths (helpers)
// =====================================================================

func TestHexToScalarBadHex(t *testing.T) {
	_, err := hexToScalar("zzzz")
	require.Error(t, err)
}

func TestHexToFixed32BadHex(t *testing.T) {
	_, err := hexToFixed32("zzzz")
	require.Error(t, err)
}

func TestHexToFixed16BadHex(t *testing.T) {
	_, err := hexToFixed16("zzzz")
	require.Error(t, err)
}

func TestStringMapKeysBadInt(t *testing.T) {
	m := map[string]*VOLEBobState{"abc": nil}
	_, err := stringMapKeys(m)
	require.Error(t, err)
}

func TestStringMapKeysNil(t *testing.T) {
	got, err := stringMapKeys[*VOLEBobState](nil)
	require.NoError(t, err)
	require.Nil(t, got)
}

func TestIntMapKeysNil(t *testing.T) {
	got := intMapKeys[string](nil)
	require.Nil(t, got)
}

func TestJsonToIntMap32BadKey(t *testing.T) {
	_, err := jsonToIntMap32(map[string]string{"abc": "00"})
	require.Error(t, err)
}

func TestJsonToIntMap32BadHex(t *testing.T) {
	_, err := jsonToIntMap32(map[string]string{"1": "zzzz"})
	require.Error(t, err)
}

func TestJsonToIntMap16BadKey(t *testing.T) {
	_, err := jsonToIntMap16(map[string]string{"abc": "00"})
	require.Error(t, err)
}

func TestJsonToIntMap16BadHex(t *testing.T) {
	_, err := jsonToIntMap16(map[string]string{"1": "zzzz"})
	require.Error(t, err)
}

func TestJsonToIntMapBytesBadKey(t *testing.T) {
	_, err := jsonToIntMapBytes(map[string]string{"abc": "00"})
	require.Error(t, err)
}

func TestJsonToIntMapBytesBadHex(t *testing.T) {
	_, err := jsonToIntMapBytes(map[string]string{"1": "zzzz"})
	require.Error(t, err)
}

func TestHexToScalarMapBadKey(t *testing.T) {
	_, err := hexToScalarMap(map[string]string{"abc": "00"})
	require.Error(t, err)
}

func TestHexToScalarMapBadHex(t *testing.T) {
	_, err := hexToScalarMap(map[string]string{"1": "zzzz"})
	require.Error(t, err)
}

func TestDecodeVOLESliceBadBase64(t *testing.T) {
	_, err := decodeVOLESlice("!!!bad!!!")
	require.Error(t, err)
}

func TestDecodeVOLESliceBadSize(t *testing.T) {
	_, err := decodeVOLESlice("AAAA")
	require.Error(t, err)
}

func TestDecodeVOLEFixedBadBase64(t *testing.T) {
	_, err := decodeVOLEFixed("!!!bad!!!")
	require.Error(t, err)
}

func TestDecodeVOLEFixedBadSize(t *testing.T) {
	_, err := decodeVOLEFixed("AAAA")
	require.Error(t, err)
}

func TestDecodeRhoFixedBadHex(t *testing.T) {
	_, err := decodeRhoFixed("zzzz")
	require.Error(t, err)
}

func TestDecodeRhoFixedBadSize(t *testing.T) {
	_, err := decodeRhoFixed("aabb")
	require.Error(t, err)
}

func TestDecodeBoolArrayBadBase64(t *testing.T) {
	_, err := decodeBoolArray("!!!bad!!!")
	require.Error(t, err)
}

func TestDecodeBoolArrayBadSize(t *testing.T) {
	_, err := decodeBoolArray("AA==")
	require.Error(t, err)
}
