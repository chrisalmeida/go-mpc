package frost

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRejectedUnmarshalPreservesReceiver covers every custom decoder except
// SignerState, whose rejection tests also finish the active signing session.
func TestRejectedUnmarshalPreservesReceiver(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		target any
		fields []string
	}{
		{"KeyShare", fullSetup(t)[1], []string{"secret_share", "public_key", "verification_share", "group_commitments"}},
		{"DKGRound1Output", &DKGRound1Output{FeldmanCommitments: [][]byte{{1}}, PairwiseCommitments: map[int][32]byte{2: {2}}, PairwiseSalts: map[int][SaltLen]byte{2: {3}}, ProofR: make([]byte, ElementLen), ProofMu: make([]byte, ScalarLen)}, []string{"feldman_commitments", "pairwise_commitments", "pairwise_salts", "proof_r", "proof_mu"}},
		{"DKGRound2Output", &DKGRound2Output{SecretShares: map[int][]byte{2: {1}}}, []string{"secret_shares"}},
		{"NonceCommitment", &NonceCommitment{HidingNonceCommitment: []byte{1}, BindingNonceCommitment: []byte{2}}, []string{"hiding_nonce_commitment", "binding_nonce_commitment"}},
		{"SignatureShare", &SignatureShare{SignerID: 1, Zi: []byte{2}}, []string{"zi"}},
		{"Signature", &Signature{R: []byte{1}, Z: []byte{2}}, []string{"r", "z"}},
		{"RefreshRound1Output", &RefreshRound1Output{FeldmanCommitments: [][]byte{{1}}, PairwiseCommitments: map[int][32]byte{2: {2}}, PairwiseSalts: map[int][SaltLen]byte{2: {3}}, SeedCommitment: [32]byte{4}, SeedSalt: [SaltLen]byte{5}}, []string{"feldman_commitments", "pairwise_commitments", "pairwise_salts", "seed_commitment", "seed_salt"}},
		{"RefreshRound2Output", &RefreshRound2Output{SecretShares: map[int][]byte{2: {1}}, Seed: [16]byte{2}}, []string{"secret_shares", "seed"}},
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
					rejected, err := json.Marshal(fields)
					require.NoError(t, err)
					err = json.Unmarshal(rejected, tc.target)
					require.Error(t, err)
					require.NotContains(t, err.Error(), "version", "field rejection must pass the version check")
					after, err := json.Marshal(tc.target)
					require.NoError(t, err)
					require.True(t, bytes.Equal(before, after), "rejected %s changed receiver", field)
				})
			}
		})
	}
}

// bad is invalid hex that passes JSON parsing but fails hex decoding.
const bad = "ZZZZ"

// valid32 is 64 hex chars (32 bytes) — valid for hex decoding.
const valid32 = "0000000000000000000000000000000000000000000000000000000000000001"

func TestUnmarshalKeyShareErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		json string
		want string
	}{
		{"bad secret_share", `{"version":1,"id":1,"secret_share":"` + bad + `","public_key":"","verification_share":"","group_commitments":[],"threshold":1,"all_ids":[1]}`, "decode secret_share"},
		{"bad public_key", `{"version":1,"id":1,"secret_share":"` + valid32 + `","public_key":"` + bad + `","verification_share":"","group_commitments":[],"threshold":1,"all_ids":[1]}`, "decode public_key"},
		{"bad verification_share", `{"version":1,"id":1,"secret_share":"` + valid32 + `","public_key":"` + valid32 + `","verification_share":"` + bad + `","group_commitments":[],"threshold":1,"all_ids":[1]}`, "decode verification_share"},
		{"bad group_commitment", `{"version":1,"id":1,"secret_share":"` + valid32 + `","public_key":"` + valid32 + `","verification_share":"` + valid32 + `","group_commitments":["` + bad + `"],"threshold":1,"all_ids":[1]}`, "decode group_commitment[0]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v KeyShare
			require.ErrorContains(t, json.Unmarshal([]byte(tc.json), &v), tc.want)
		})
	}
}

func TestUnmarshalSignerStateErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		json string
	}{
		{"bad json", `not json`},
		{"bad blacklist key", `{"version":1,"key_share":null,"blacklist":{"notint":true}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v SignerState
			err := json.Unmarshal([]byte(tc.json), &v)
			require.Error(t, err)
			if tc.name == "bad blacklist key" {
				require.ErrorContains(t, err, "notint")
			}
		})
	}
}

func TestUnmarshalDKGRound1OutputErrors(t *testing.T) {
	t.Parallel()
	// Everything except the proof fields is valid in this prefix.
	const okPrefix = `{"feldman_commitments":[],"pairwise_commitments":{},"pairwise_salts":{}`
	cases := []struct {
		name string
		json string
		want string // substring the error must contain ("" = any error)
	}{
		{"bad feldman", `{"feldman_commitments":["` + bad + `"],"pairwise_commitments":{},"pairwise_salts":{}}`, ""},
		{"bad pairwise_commitment", `{"feldman_commitments":[],"pairwise_commitments":{"1":"` + bad + `"},"pairwise_salts":{}}`, ""},
		{"bad pairwise_salt", `{"feldman_commitments":[],"pairwise_commitments":{},"pairwise_salts":{"1":"` + bad + `"}}`, ""},
		{"bad pairwise_commitment key", `{"feldman_commitments":[],"pairwise_commitments":{"abc":"aa"},"pairwise_salts":{}}`, ""},
		{"bad pairwise_salt key", `{"feldman_commitments":[],"pairwise_commitments":{},"pairwise_salts":{"abc":"aa"}}`, ""},
		// Proof of knowledge σ_i = (R_i, μ_i): strict 32-byte lengths.
		{"missing proof fields", okPrefix + `}`, "proof_r"},
		{"missing proof_r", okPrefix + `,"proof_mu":"` + valid32 + `"}`, "proof_r"},
		{"bad proof_r hex", okPrefix + `,"proof_r":"` + bad + `","proof_mu":"` + valid32 + `"}`, "proof_r"},
		{"short proof_r", okPrefix + `,"proof_r":"aabb","proof_mu":"` + valid32 + `"}`, "proof_r: expected 32 bytes, got 2"},
		{"long proof_r", okPrefix + `,"proof_r":"` + valid32 + `00","proof_mu":"` + valid32 + `"}`, "proof_r: expected 32 bytes, got 33"},
		{"missing proof_mu", okPrefix + `,"proof_r":"` + valid32 + `"}`, "proof_mu"},
		{"bad proof_mu hex", okPrefix + `,"proof_r":"` + valid32 + `","proof_mu":"` + bad + `"}`, "proof_mu"},
		{"short proof_mu", okPrefix + `,"proof_r":"` + valid32 + `","proof_mu":"aabb"}`, "proof_mu: expected 32 bytes, got 2"},
		{"long proof_mu", okPrefix + `,"proof_r":"` + valid32 + `","proof_mu":"` + valid32 + `00"}`, "proof_mu: expected 32 bytes, got 33"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v DKGRound1Output
			err := json.Unmarshal([]byte(tc.json), &v)
			require.Error(t, err)
			if tc.want != "" {
				require.ErrorContains(t, err, tc.want)
			}
		})
	}

	// The same document with 32-byte proof fields parses.
	var v DKGRound1Output
	require.NoError(t, json.Unmarshal([]byte(okPrefix+`,"proof_r":"`+valid32+`","proof_mu":"`+valid32+`"}`), &v))
	require.Len(t, v.ProofR, ElementLen)
	require.Len(t, v.ProofMu, ScalarLen)
}

func TestUnmarshalDKGRound2OutputErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		json string
	}{
		{"bad share hex", `{"secret_shares":{"1":"` + bad + `"}}`},
		{"bad share key", `{"secret_shares":{"abc":"aa"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v DKGRound2Output
			require.Error(t, json.Unmarshal([]byte(tc.json), &v))
		})
	}
}

func TestUnmarshalNonceCommitmentErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		json string
	}{
		{"bad hiding", `{"hiding_nonce_commitment":"` + bad + `","binding_nonce_commitment":""}`},
		{"bad binding", `{"hiding_nonce_commitment":"aa","binding_nonce_commitment":"` + bad + `"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v NonceCommitment
			require.Error(t, json.Unmarshal([]byte(tc.json), &v))
		})
	}
}

func TestUnmarshalSignatureShareErrors(t *testing.T) {
	t.Parallel()
	var v SignatureShare
	require.Error(t, json.Unmarshal([]byte(`{"signer_id":1,"zi":"`+bad+`"}`), &v))
}

func TestUnmarshalRefreshRound1OutputErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		json string
	}{
		{"bad feldman", `{"feldman_commitments":["` + bad + `"],"pairwise_commitments":{},"pairwise_salts":{},"seed_commitment":"","seed_salt":""}`},
		{"bad pairwise_commitment", `{"feldman_commitments":[],"pairwise_commitments":{"1":"` + bad + `"},"pairwise_salts":{},"seed_commitment":"","seed_salt":""}`},
		{"bad pairwise_salt", `{"feldman_commitments":[],"pairwise_commitments":{},"pairwise_salts":{"1":"` + bad + `"},"seed_commitment":"","seed_salt":""}`},
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
	t.Parallel()
	cases := []struct {
		name string
		json string
	}{
		{"bad share", `{"secret_shares":{"1":"` + bad + `"},"seed":""}`},
		{"bad seed", `{"secret_shares":{},"seed":"` + bad + `"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v RefreshRound2Output
			require.Error(t, json.Unmarshal([]byte(tc.json), &v))
		})
	}
}

func TestUnmarshalSignatureErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		json string
	}{
		{"bad r", `{"r":"` + bad + `","z":""}`},
		{"bad z", `{"r":"aa","z":"` + bad + `"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v Signature
			require.Error(t, json.Unmarshal([]byte(tc.json), &v))
		})
	}
}
