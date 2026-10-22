package dkls23

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

// TestRejectedUnmarshalPreservesReceiver checks the remaining custom wire
// decoders in addition to the live-session import tests. A late decode error
// must not publish earlier fields or zero the field whose decoding failed.
func TestRejectedUnmarshalPreservesReceiver(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	var one btcec.ModNScalar
	one.SetInt(1)
	bob := &VOLEBobState{Chi: one, Gamma: make([][Ell + Rho][32]byte, 1)}
	bob.Beta[0], bob.Gamma[0][0][0] = true, 1
	alice := &VOLEAliceState{Alpha0: bob.Gamma, Alpha1: bob.Gamma, C_u: one, C_v: one}
	multiply := &VOLEMultiplyMsg{SID: "preserve", Mu: [32]byte{1}}
	multiply.ATilde[0][0][0], multiply.Eta[0][0] = 1, 1
	ote := &OTExtReceiverMsg{U: make([][XiExt / 8]byte, LambdaC), XBar: [16]byte{1}, TBar: [16]byte{2}}
	ote.U[0][0] = 1
	for _, tc := range []struct {
		name   string
		target any
		fields []string
	}{
		{"DKGRound1Output", &DKGRound1Output{FeldmanCommitment: [32]byte{1}, PairwiseCommitments: map[int][32]byte{2: {2}}}, []string{"feldman_commitment", "pairwise_commitments"}},
		{"DKGRound2Output", &DKGRound2Output{FeldmanCommitments: [][]byte{{1}}, FeldmanSalt: [32]byte{2}, SecretShares: map[int][]byte{2: {3}}, PairwiseSalts: map[int][SaltLen]byte{2: {4}}}, []string{"feldman_commitments", "feldman_salt", "secret_shares", "pairwise_salts"}},
		{"BaseOTSenderSeeds", setups[1].BobBaseOT[2], []string{"seeds0", "seeds1"}},
		{"BaseOTReceiverSeeds", setups[1].AliceBaseOT[2], []string{"seeds", "sigma"}},
		{"OTExtReceiverMsg", ote, []string{"u", "x_bar", "t_bar"}},
		{"VOLEBobState", bob, []string{"beta", "chi", "gamma"}},
		{"VOLEAliceState", alice, []string{"alpha0", "alpha1", "c_u", "c_v"}},
		{"VOLEMultiplyMsg", multiply, []string{"a_tilde", "eta", "mu"}},
		{"Round1Msg", &Round1Msg{Commitment: [32]byte{1}, OTExt: ote}, []string{"commitment", "ot_ext"}},
		{"Round2Msg", &Round2Msg{Decommitment: []byte{1}, Salt: [SaltLen]byte{2}, VoleMsg: multiply, GammaU: []byte{3}, GammaV: []byte{4}, Psi: []byte{5}, PKi: []byte{6}}, []string{"decommitment", "salt", "vole_msg", "gamma_u", "gamma_v", "psi", "pki"}},
		{"Round3Msg", &Round3Msg{W_i: []byte{1}, U_i: []byte{2}}, []string{"w_i", "u_i"}},
		{"RefreshRound1Output", &RefreshRound1Output{FeldmanCommitments: [][]byte{{1}}, PairwiseCommitments: map[int][32]byte{2: {2}}, PairwiseSalts: map[int][SaltLen]byte{2: {3}}, SeedCommitment: [32]byte{4}, SeedSalt: [SaltLen]byte{5}}, []string{"feldman_commitments", "pairwise_commitments", "pairwise_salts", "seed_commitment", "seed_salt"}},
		{"RefreshRound2Output", &RefreshRound2Output{SecretShares: map[int][]byte{2: {1}}, Seed: [16]byte{2}}, []string{"secret_shares", "seed"}},
		{"FZeroCommitMsg", &FZeroCommitMsg{Commitment: [32]byte{1}}, []string{"commitment"}},
		{"FZeroRevealMsg", &FZeroRevealMsg{Seed: [16]byte{1}, Salt: [SaltLen]byte{2}}, []string{"seed", "salt"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, err := json.Marshal(tc.target)
			require.NoError(t, err)
			for _, field := range tc.fields {
				t.Run(field, func(t *testing.T) {
					require.NoError(t, json.Unmarshal(before, tc.target))
					var fields map[string]json.RawMessage
					require.NoError(t, json.Unmarshal(before, &fields))
					original, ok := fields[field]
					require.True(t, ok, "fixture must contain %s", field)
					switch original[0] {
					case '"':
						fields[field] = json.RawMessage(`"ZZ"`)
					case '[':
						fields[field] = json.RawMessage(`["ZZ"]`)
					case '{':
						fields[field] = json.RawMessage(`{"invalid":"ZZ"}`)
					default:
						t.Fatalf("unsupported fixture field %s", field)
					}
					// A full-size U array reaches row decoding rather than merely
					// failing the row-count check.
					if field == "u" {
						rows := make([]string, LambdaC)
						for i := range rows {
							rows[i] = strings.Repeat("00", XiExt/8)
						}
						rows[LambdaC-1] = "ZZ"
						fields[field], err = json.Marshal(rows)
						require.NoError(t, err)
					}
					rejected, err := json.Marshal(fields)
					require.NoError(t, err)
					require.Error(t, json.Unmarshal(rejected, tc.target))
					after, err := json.Marshal(tc.target)
					require.NoError(t, err)
					require.True(t, bytes.Equal(before, after), "rejected %s changed receiver", field)
				})
			}
		})
	}
}

// bad is invalid hex that passes JSON parsing but fails hex/base64 decoding.
const bad = "ZZZZ"

// valid32 is 64 hex chars (32 bytes) — valid for hexToFixed32 / hexToScalar.
const valid32 = "0000000000000000000000000000000000000000000000000000000000000001"

// valid16 is 32 hex chars (16 bytes) — valid for hexToFixed16.
const valid16 = "00000000000000000000000000000001"

func TestUnmarshalDKGRound1OutputErrors(t *testing.T) {
	cases := []struct {
		name string
		json string
	}{
		{"bad feldman_commitment", `{"feldman_commitment":"` + bad + `","pairwise_commitments":{}}`},
		{"short feldman_commitment", `{"feldman_commitment":"aabb","pairwise_commitments":{}}`},
		{"bad pairwise_commitments", `{"feldman_commitment":"` + valid32 + `","pairwise_commitments":{"1":"` + bad + `"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v DKGRound1Output
			require.Error(t, json.Unmarshal([]byte(tc.json), &v))
		})
	}
}

func TestUnmarshalDKGRound2OutputErrors(t *testing.T) {
	cases := []struct {
		name string
		json string
	}{
		{"bad feldman", `{"feldman_commitments":["` + bad + `"],"feldman_salt":"","secret_shares":{},"pairwise_salts":{}}`},
		{"bad feldman_salt", `{"feldman_commitments":[],"feldman_salt":"` + bad + `","secret_shares":{},"pairwise_salts":{}}`},
		{"bad secret_shares", `{"feldman_commitments":[],"feldman_salt":"` + valid32 + `","secret_shares":{"1":"` + bad + `"},"pairwise_salts":{}}`},
		{"bad pairwise_salts", `{"feldman_commitments":[],"feldman_salt":"` + valid32 + `","secret_shares":{},"pairwise_salts":{"1":"` + bad + `"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v DKGRound2Output
			require.Error(t, json.Unmarshal([]byte(tc.json), &v))
		})
	}
}

func TestUnmarshalBaseOTSeedsErrors(t *testing.T) {
	t.Run("receiver bad seeds", func(t *testing.T) {
		var v BaseOTReceiverSeeds
		require.Error(t, json.Unmarshal([]byte(`{"seeds":["`+bad+`"],"sigma":""}`), &v))
	})
	t.Run("receiver bad sigma", func(t *testing.T) {
		seeds := `"` + valid32 + `"`
		for i := 1; i < LambdaC; i++ {
			seeds += `,"` + valid32 + `"`
		}
		var v BaseOTReceiverSeeds
		require.Error(t, json.Unmarshal([]byte(`{"seeds":[`+seeds+`],"sigma":"`+bad+`"}`), &v))
		require.Error(t, json.Unmarshal([]byte(`{"seeds":[`+seeds+`],"sigma":"AA=="}`), &v))
	})
	t.Run("sender bad seeds0", func(t *testing.T) {
		var v BaseOTSenderSeeds
		require.Error(t, json.Unmarshal([]byte(`{"seeds0":["`+bad+`"],"seeds1":[]}`), &v))
	})
	t.Run("sender bad seeds1", func(t *testing.T) {
		seeds := `"` + valid32 + `"`
		for i := 1; i < LambdaC; i++ {
			seeds += `,"` + valid32 + `"`
		}
		var v BaseOTSenderSeeds
		require.Error(t, json.Unmarshal([]byte(`{"seeds0":[`+seeds+`],"seeds1":["`+bad+`"]}`), &v))
	})
	t.Run("not json", func(t *testing.T) {
		var r BaseOTReceiverSeeds
		require.Error(t, json.Unmarshal([]byte(`nope`), &r))
		var s BaseOTSenderSeeds
		require.Error(t, json.Unmarshal([]byte(`nope`), &s))
	})
}

func TestUnmarshalVOLEBobStateErrors(t *testing.T) {
	cases := []struct {
		name string
		json string
	}{
		{"bad beta", `{"beta":"` + bad + `","chi":"","gamma":""}`},
		{"bad chi", `{"beta":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==","chi":"` + bad + `","gamma":""}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v VOLEBobState
			require.Error(t, json.Unmarshal([]byte(tc.json), &v))
		})
	}
}

func TestUnmarshalVOLEAliceStateErrors(t *testing.T) {
	cases := []struct {
		name string
		json string
	}{
		{"bad alpha0", `{"alpha0":"` + bad + `","alpha1":"","c_u":"","c_v":""}`},
		{"bad alpha1", `{"alpha0":"","alpha1":"` + bad + `","c_u":"","c_v":""}`},
		{"bad c_u", `{"alpha0":"","alpha1":"","c_u":"` + bad + `","c_v":""}`},
		{"bad c_v", `{"alpha0":"","alpha1":"","c_u":"` + valid32 + `","c_v":"` + bad + `"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v VOLEAliceState
			require.Error(t, json.Unmarshal([]byte(tc.json), &v))
		})
	}
}

func TestUnmarshalVOLEMultiplyMsgErrors(t *testing.T) {
	cases := []struct {
		name string
		json string
	}{
		{"bad a_tilde", `{"sid":"x","a_tilde":"` + bad + `","eta":"","mu":""}`},
		{"bad eta", `{"sid":"x","a_tilde":"","eta":"` + bad + `","mu":""}`},
		{"bad mu", `{"sid":"x","a_tilde":"","eta":"` + valid32 + valid32 + `","mu":"` + bad + `"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v VOLEMultiplyMsg
			require.Error(t, json.Unmarshal([]byte(tc.json), &v))
		})
	}
}

func TestUnmarshalRound1MsgErrors(t *testing.T) {
	cases := []struct {
		name string
		json string
	}{
		{"bad commitment", `{"commitment":"` + bad + `","ot_ext":null}`},
		{"bad ot_ext", `{"commitment":"` + valid32 + `","ot_ext":{"u":["` + bad + `"],"x_bar":"","t_bar":""}}`},
		{"not json", `nope`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v Round1Msg
			require.Error(t, json.Unmarshal([]byte(tc.json), &v))
		})
	}
}

func TestUnmarshalRound1StateErrors(t *testing.T) {
	cases := []struct {
		name string
		json string
	}{
		{"bad r_i", `{"sig_id":"x","signers":[1],"r_i":"` + bad + `","phi_i":"","r_i_point":"","com":"","salt":"","zeta_i":""}`},
		{"bad phi_i", `{"sig_id":"x","signers":[1],"r_i":"` + valid32 + `","phi_i":"` + bad + `","r_i_point":"","com":"","salt":"","zeta_i":""}`},
		{"bad r_i_point", `{"sig_id":"x","signers":[1],"r_i":"` + valid32 + `","phi_i":"` + valid32 + `","r_i_point":"` + bad + `","com":"","salt":"","zeta_i":""}`},
		{"bad com", `{"sig_id":"x","signers":[1],"r_i":"` + valid32 + `","phi_i":"` + valid32 + `","r_i_point":"aa","com":"` + bad + `","salt":"","zeta_i":""}`},
		{"bad salt", `{"sig_id":"x","signers":[1],"r_i":"` + valid32 + `","phi_i":"` + valid32 + `","r_i_point":"aa","com":"` + valid32 + `","salt":"` + bad + `","zeta_i":""}`},
		{"bad zeta_i", `{"sig_id":"x","signers":[1],"r_i":"` + valid32 + `","phi_i":"` + valid32 + `","r_i_point":"aa","com":"` + valid32 + `","salt":"` + valid32 + `","zeta_i":"` + bad + `"}`},
		{"bad vole_bob key", `{"sig_id":"x","signers":[1],"r_i":"` + valid32 + `","phi_i":"` + valid32 + `","r_i_point":"aa","com":"` + valid32 + `","salt":"` + valid32 + `","zeta_i":"` + valid32 + `","vole_bob_for_round2":{"abc":null}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v Round1State
			require.Error(t, json.Unmarshal([]byte(tc.json), &v))
		})
	}
}

func TestUnmarshalRound2StateErrors(t *testing.T) {
	cases := []struct {
		name string
		json string
	}{
		{"bad sk_i", `{"round1_state":null,"sk_i":"` + bad + `","c_u":{},"c_v":{},"round1_commits":{}}`},
		{"bad c_u", `{"round1_state":null,"sk_i":"` + valid32 + `","c_u":{"1":"` + bad + `"},"c_v":{},"round1_commits":{}}`},
		{"bad c_v", `{"round1_state":null,"sk_i":"` + valid32 + `","c_u":{},"c_v":{"1":"` + bad + `"},"round1_commits":{}}`},
		{"bad round1_commits", `{"round1_state":null,"sk_i":"` + valid32 + `","c_u":{},"c_v":{},"round1_commits":{"1":"` + bad + `"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v Round2State
			require.Error(t, json.Unmarshal([]byte(tc.json), &v))
		})
	}
}

func TestUnmarshalRound2MsgErrors(t *testing.T) {
	cases := []struct {
		name string
		json string
	}{
		{"bad decommitment", `{"decommitment":"` + bad + `","salt":"","vole_msg":null,"gamma_u":"","gamma_v":"","psi":"","pki":""}`},
		{"bad salt", `{"decommitment":"aa","salt":"` + bad + `","vole_msg":null,"gamma_u":"","gamma_v":"","psi":"","pki":""}`},
		{"bad gamma_u", `{"decommitment":"aa","salt":"` + valid32 + `","vole_msg":null,"gamma_u":"` + bad + `","gamma_v":"","psi":"","pki":""}`},
		{"bad gamma_v", `{"decommitment":"aa","salt":"` + valid32 + `","vole_msg":null,"gamma_u":"bb","gamma_v":"` + bad + `","psi":"","pki":""}`},
		{"bad psi", `{"decommitment":"aa","salt":"` + valid32 + `","vole_msg":null,"gamma_u":"bb","gamma_v":"cc","psi":"` + bad + `","pki":""}`},
		{"bad pki", `{"decommitment":"aa","salt":"` + valid32 + `","vole_msg":null,"gamma_u":"bb","gamma_v":"cc","psi":"dd","pki":"` + bad + `"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v Round2Msg
			require.Error(t, json.Unmarshal([]byte(tc.json), &v))
		})
	}
}

func TestUnmarshalRound3MsgErrors(t *testing.T) {
	cases := []struct {
		name string
		json string
	}{
		{"bad w_i", `{"w_i":"` + bad + `","u_i":""}`},
		{"bad u_i", `{"w_i":"aa","u_i":"` + bad + `"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v Round3Msg
			require.Error(t, json.Unmarshal([]byte(tc.json), &v))
		})
	}
}

func TestUnmarshalRefreshRound1OutputErrors(t *testing.T) {
	cases := []struct {
		name string
		json string
	}{
		{"bad feldman", `{"feldman_commitments":["` + bad + `"],"pairwise_commitments":{},"pairwise_salts":{},"seed_commitment":"","seed_salt":""}`},
		{"bad pairwise_commitments", `{"feldman_commitments":[],"pairwise_commitments":{"1":"` + bad + `"},"pairwise_salts":{},"seed_commitment":"","seed_salt":""}`},
		{"bad pairwise_salts", `{"feldman_commitments":[],"pairwise_commitments":{},"pairwise_salts":{"1":"` + bad + `"},"seed_commitment":"","seed_salt":""}`},
		{"bad seed_commitment", `{"feldman_commitments":[],"pairwise_commitments":{},"pairwise_salts":{},"seed_commitment":"` + bad + `","seed_salt":""}`},
		{"bad seed_salt", `{"feldman_commitments":[],"pairwise_commitments":{},"pairwise_salts":{},"seed_commitment":"` + valid32 + `","seed_salt":"` + bad + `"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v RefreshRound1Output
			require.Error(t, json.Unmarshal([]byte(tc.json), &v))
		})
	}
}

func TestUnmarshalRefreshRound2OutputErrors(t *testing.T) {
	cases := []struct {
		name string
		json string
	}{
		{"bad secret_shares", `{"secret_shares":{"1":"` + bad + `"},"seed":""}`},
		{"bad seed", `{"secret_shares":{},"seed":"` + bad + `"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v RefreshRound2Output
			require.Error(t, json.Unmarshal([]byte(tc.json), &v))
		})
	}
}

func TestUnmarshalSignerSetupErrors(t *testing.T) {
	const head = `{"version":1,"my_id":1,"all_ids":[1],`
	cases := []struct {
		name string
		json string
	}{
		{"missing version", `{"my_id":1,"all_ids":[1],"share":"` + valid32 + `","pub_key":"aa","threshold":1}`},
		{"wrong version", `{"version":2,"my_id":1,"all_ids":[1],"share":"` + valid32 + `","pub_key":"aa","threshold":1}`},
		{"bad share", head + `"share":"` + bad + `","pub_key":"","threshold":1}`},
		{"bad pub_key", head + `"share":"` + valid32 + `","pub_key":"` + bad + `","threshold":1}`},
		{"bad alice_base_ot key", head + `"share":"` + valid32 + `","pub_key":"aa","threshold":1,"alice_base_ot":{"abc":null}}`},
		{"bad alice_base_ot value", head + `"share":"` + valid32 + `","pub_key":"aa","threshold":1,"alice_base_ot":{"2":{"seeds":["` + bad + `"],"sigma":""}}}`},
		{"bad bob_base_ot key", head + `"share":"` + valid32 + `","pub_key":"aa","threshold":1,"bob_base_ot":{"abc":null}}`},
		{"bad bob_base_ot value", head + `"share":"` + valid32 + `","pub_key":"aa","threshold":1,"bob_base_ot":{"2":{"seeds0":["` + bad + `"],"seeds1":[]}}}`},
		{"bad fzero_seeds", head + `"share":"` + valid32 + `","pub_key":"aa","threshold":1,"fzero_seeds":{"1":"` + bad + `"}}`},
		{"bad blacklist key", head + `"share":"` + valid32 + `","pub_key":"aa","threshold":1,"blacklist":{"notint":true}}`},
		{"session stage too low", head + `"share":"` + valid32 + `","pub_key":"aa","threshold":1,"session_ids":{"sid":0}}`},
		{"session stage too high", head + `"share":"` + valid32 + `","pub_key":"aa","threshold":1,"session_ids":{"sid":4}}`},
		{"empty session id", head + `"share":"` + valid32 + `","pub_key":"aa","threshold":1,"session_ids":{"":1}}`},
		{"not json", `nope`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v SignerSetup
			require.Error(t, json.Unmarshal([]byte(tc.json), &v))
		})
	}
}

func TestUnmarshalFZeroCommitMsgErrors(t *testing.T) {
	var v FZeroCommitMsg
	require.Error(t, json.Unmarshal([]byte(`{"commitment":"`+bad+`"}`), &v))
}

func TestUnmarshalFZeroRevealMsgErrors(t *testing.T) {
	cases := []struct {
		name string
		json string
	}{
		{"bad seed", `{"seed":"` + bad + `","salt":""}`},
		{"bad salt", `{"seed":"` + valid16 + `","salt":"` + bad + `"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v FZeroRevealMsg
			require.Error(t, json.Unmarshal([]byte(tc.json), &v))
		})
	}
}
