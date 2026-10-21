package dkls23

import (
	"encoding/json"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

// --- UnmarshalJSON fuzz targets ---
// These verify that arbitrary byte inputs never panic during deserialization.

func FuzzUnmarshalVOLEBobState(f *testing.F) {
	f.Add([]byte(`{"beta":"","chi":"","gamma":""}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var s VOLEBobState
		_ = json.Unmarshal(data, &s)
	})
}

func FuzzUnmarshalVOLEAliceState(f *testing.F) {
	f.Add([]byte(`{"alpha0":"","alpha1":"","c_u":"","c_v":""}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var s VOLEAliceState
		_ = json.Unmarshal(data, &s)
	})
}

func FuzzUnmarshalVOLEMultiplyMsg(f *testing.F) {
	f.Add([]byte(`{"sid":"","a_tilde":"","eta":"","mu":""}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var m VOLEMultiplyMsg
		_ = json.Unmarshal(data, &m)
	})
}

func FuzzUnmarshalRound1Msg(f *testing.F) {
	f.Add([]byte(`{"commitment":"","ot_ext":null}`))
	f.Add([]byte(`{"commitment":"","ot_ext":{"u":[],"x_bar":"","t_bar":""}}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var m Round1Msg
		_ = json.Unmarshal(data, &m)
	})
}

func FuzzUnmarshalRound1State(f *testing.F) {
	f.Add([]byte(`{"sig_id":"","signers":[],"r_i":"","phi_i":"","r_i_point":"","com":"","salt":"","zeta_i":""}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var s Round1State
		_ = json.Unmarshal(data, &s)
	})
}

func FuzzUnmarshalRound2State(f *testing.F) {
	f.Add([]byte(`{"round1_state":null,"sk_i":"","c_u":{},"c_v":{},"round1_commits":{}}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var s Round2State
		_ = json.Unmarshal(data, &s)
	})
}

func FuzzUnmarshalSignerSetup(f *testing.F) {
	f.Add([]byte(`{"version":1,"my_id":1,"all_ids":[1],"share":"","pub_key":"","threshold":1}`))
	f.Add([]byte(`{"version":1,"alice_base_ot":{"2":{"seeds":[],"sigma":""}},"bob_base_ot":{"2":{"seeds0":[],"seeds1":[]}}}`))
	f.Add([]byte(`{"version":1,"my_id":1,"all_ids":[1],"share":"","pub_key":"","threshold":1,"session_ids":{"sid":2}}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var s SignerSetup
		_ = json.Unmarshal(data, &s)
	})
}

func FuzzUnmarshalBaseOTSeeds(f *testing.F) {
	f.Add([]byte(`{"seeds":[],"sigma":""}`))
	f.Add([]byte(`{"seeds0":[],"seeds1":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var r BaseOTReceiverSeeds
		_ = json.Unmarshal(data, &r)
		var s BaseOTSenderSeeds
		_ = json.Unmarshal(data, &s)
	})
}

func FuzzUnmarshalDKGRound1Output(f *testing.F) {
	f.Add([]byte(`{"feldman_commitment":"","pairwise_commitments":{}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var o DKGRound1Output
		_ = json.Unmarshal(data, &o)
	})
}

func FuzzUnmarshalDKGRound2Output(f *testing.F) {
	f.Add([]byte(`{"feldman_commitments":[],"feldman_salt":"","secret_shares":{},"pairwise_salts":{}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var o DKGRound2Output
		_ = json.Unmarshal(data, &o)
	})
}

func FuzzUnmarshalRefreshRound1Output(f *testing.F) {
	f.Add([]byte(`{"feldman_commitments":[],"pairwise_commitments":{},"pairwise_salts":{},"seed_commitment":"","seed_salt":""}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var o RefreshRound1Output
		_ = json.Unmarshal(data, &o)
	})
}

// --- Protocol input fuzz targets ---

func FuzzHexToScalar(f *testing.F) {
	f.Add("")
	f.Add("00")
	f.Add("ff")
	f.Add("0000000000000000000000000000000000000000000000000000000000000001")
	f.Add("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
	f.Add("not-hex")
	f.Add("zz")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = hexToScalar(s)
	})
}

func FuzzFeldmanVerify(f *testing.F) {
	// Seed with a valid point
	f.Add([]byte{0x02}, uint8(1))
	f.Fuzz(func(t *testing.T, commitData []byte, x uint8) {
		if x == 0 || len(commitData) < 33 {
			return
		}
		var share btcec.ModNScalar
		share.SetInt(uint32(x))
		// Single commitment — will almost always fail verification,
		// but must never panic.
		_ = feldmanVerify(&share, int(x), [][]byte{commitData})
	})
}

func FuzzGadgetInnerProduct(f *testing.F) {
	f.Add(make([]byte, 52)) // Xi/8 = 52
	f.Fuzz(func(t *testing.T, betaBytes []byte) {
		if len(betaBytes) < (Xi+7)/8 {
			return
		}
		var beta [Xi]bool
		for j := 0; j < Xi; j++ {
			beta[j] = (betaBytes[j/8]>>(uint(j)%8))&1 == 1
		}
		_ = GadgetInnerProduct(beta)
	})
}

func FuzzValidatePartyIDs(f *testing.F) {
	f.Add(1, 2, 3)
	f.Add(0, 1, 2)
	f.Add(-1, 1, 2)
	f.Add(1, 1, 2) // duplicate
	f.Fuzz(func(t *testing.T, a, b, c int) {
		_ = validatePartyIDs([]int{a, b, c}, "fuzz")
	})
}
