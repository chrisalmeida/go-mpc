package dkls23

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

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
