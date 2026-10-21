package frost

import (
	"encoding/json"
	"testing"
)

// --- UnmarshalJSON fuzz targets ---
// These verify that arbitrary byte inputs never panic during deserialization.

func FuzzUnmarshalKeyShare(f *testing.F) {
	f.Add([]byte(`{"id":1,"secret_share":"","public_key":"","verification_share":"","group_commitments":[],"threshold":1,"all_ids":[1]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var v KeyShare
		_ = json.Unmarshal(data, &v)
	})
}

func FuzzUnmarshalSignerState(f *testing.F) {
	f.Add([]byte(`{"key_share":null,"blacklist":{}}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var v SignerState
		_ = json.Unmarshal(data, &v)
	})
}

func FuzzUnmarshalDKGRound1Output(f *testing.F) {
	f.Add([]byte(`{"feldman_commitments":[],"pairwise_commitments":{},"pairwise_salts":{}}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var v DKGRound1Output
		_ = json.Unmarshal(data, &v)
	})
}

func FuzzUnmarshalDKGRound2Output(f *testing.F) {
	f.Add([]byte(`{"secret_shares":{}}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var v DKGRound2Output
		_ = json.Unmarshal(data, &v)
	})
}

func FuzzUnmarshalNonceCommitment(f *testing.F) {
	f.Add([]byte(`{"hiding_nonce_commitment":"","binding_nonce_commitment":""}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var v NonceCommitment
		_ = json.Unmarshal(data, &v)
	})
}

func FuzzUnmarshalSignatureShare(f *testing.F) {
	f.Add([]byte(`{"signer_id":1,"zi":""}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var v SignatureShare
		_ = json.Unmarshal(data, &v)
	})
}

func FuzzUnmarshalSignature(f *testing.F) {
	f.Add([]byte(`{"r":"","z":""}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var v Signature
		_ = json.Unmarshal(data, &v)
	})
}

// --- Protocol input fuzz targets ---

func FuzzFeldmanVerify(f *testing.F) {
	f.Add([]byte{0x01}, uint8(1))
	f.Add(make([]byte, 32), uint8(1))
	f.Fuzz(func(t *testing.T, commitData []byte, x uint8) {
		if x == 0 {
			return
		}
		share := scalarFromInt(int(x))
		// A received commitment vector is parsed with deserializeElement
		// first (RFC 9591 Section 6.1); garbage must be rejected there, and
		// anything that parses must verify (or fail) without panicking.
		points, err := parseFeldmanCommitments([][]byte{commitData})
		if err != nil {
			return
		}
		_ = feldmanVerify(share, int(x), points)
	})
}

func FuzzUnmarshalRefreshRound1Output(f *testing.F) {
	f.Add([]byte(`{"feldman_commitments":[],"pairwise_commitments":{},"pairwise_salts":{},"seed_commitment":"","seed_salt":""}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var v RefreshRound1Output
		_ = json.Unmarshal(data, &v)
	})
}

func FuzzUnmarshalRefreshRound2Output(f *testing.F) {
	f.Add([]byte(`{"secret_shares":{},"seed":""}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var v RefreshRound2Output
		_ = json.Unmarshal(data, &v)
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

func FuzzH1(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("test"))
	f.Add(make([]byte, 256))
	f.Fuzz(func(t *testing.T, data []byte) {
		s := H1(data)
		if s == nil {
			t.Fatal("H1 returned nil")
		}
	})
}

func FuzzVerify(f *testing.F) {
	f.Add(make([]byte, 32), make([]byte, 32), make([]byte, 32), []byte("msg"))
	f.Fuzz(func(t *testing.T, pk, r, z, msg []byte) {
		sig := &Signature{R: r, Z: z}
		// Must never panic, even on garbage inputs.
		_ = Verify(pk, msg, sig)
	})
}
