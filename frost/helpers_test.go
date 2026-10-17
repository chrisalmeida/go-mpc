package frost

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/require"
)

// dkgTestContext is the DKG context string Φ shared by all test parties.
var dkgTestContext = []byte("go-mpc frost tests: DKG session context")

// buildDKG runs a complete distributed DKG for the given party IDs and threshold.
// Returns a KeyShare per party.
func buildDKG(allIDs []int, threshold int) (map[int]*KeyShare, error) {
	configs := make(map[int]DKGPartyConfig)
	coeffs := make(map[int][]*edwards25519.Scalar)
	r1 := make(map[int]*DKGRound1Output)

	for _, id := range allIDs {
		cfg := DKGPartyConfig{MyID: id, AllIDs: allIDs, Threshold: threshold, Context: dkgTestContext}
		configs[id] = cfg
		out, c, err := DKGRound1(cfg)
		if err != nil {
			return nil, err
		}
		r1[id] = out
		coeffs[id] = c
	}

	r2 := make(map[int]*DKGRound2Output)
	for _, id := range allIDs {
		out, err := DKGRound2(configs[id], coeffs[id], r1)
		if err != nil {
			return nil, err
		}
		r2[id] = out
	}

	keyShares := make(map[int]*KeyShare)
	for _, id := range allIDs {
		ks, err := DKGFinalize(configs[id], coeffs[id], r1, r2)
		if err != nil {
			return nil, err
		}
		keyShares[id] = ks
	}
	return keyShares, nil
}

// --- Cached 3-of-3 setup ---

var (
	cached3of3Once sync.Once
	cached3of3JSON map[int][]byte
	cached3of3Err  error
)

// fullSetup returns a 3-of-3 KeyShare per party. The DKG runs once and is cached;
// each call returns an independent deep copy.
func fullSetup(t testing.TB) map[int]*KeyShare {
	t.Helper()
	cached3of3Once.Do(func() {
		shares, err := buildDKG([]int{1, 2, 3}, 3)
		if err != nil {
			cached3of3Err = err
			return
		}
		cached3of3JSON = make(map[int][]byte)
		for id, ks := range shares {
			b, err := json.Marshal(ks)
			if err != nil {
				cached3of3Err = err
				return
			}
			cached3of3JSON[id] = b
		}
	})
	require.NoError(t, cached3of3Err)
	result := make(map[int]*KeyShare)
	for id, b := range cached3of3JSON {
		var ks KeyShare
		err := json.Unmarshal(b, &ks)
		require.NoError(t, err)
		result[id] = &ks
	}
	return result
}

// fullSign runs a complete signing session and returns the signature.
func fullSign(t testing.TB, keyShares map[int]*KeyShare, signers []int, msg []byte) *Signature {
	t.Helper()

	signerStates := make(map[int]*SignerState)
	for _, id := range signers {
		signerStates[id] = NewSignerState(keyShares[id])
	}

	// Round 1
	r1States := make(map[int]*Round1State)
	allCommitments := make(map[int]*NonceCommitment)
	for _, id := range signers {
		state, comm, err := SignRound1(signerStates[id], signers)
		require.NoError(t, err)
		r1States[id] = state
		allCommitments[id] = comm
	}

	// Round 2
	allShares := make(map[int]*SignatureShare)
	input := &Round2Input{Message: msg, AllCommitments: allCommitments}
	for _, id := range signers {
		share, err := SignRound2(signerStates[id], r1States[id], input)
		require.NoError(t, err)
		allShares[id] = share
	}

	// Build verification shares map
	verShares := make(map[int][]byte)
	for _, id := range signers {
		verShares[id] = keyShares[id].VerificationShare
	}

	// Aggregate
	sig, err := Aggregate(allCommitments, allShares, msg, keyShares[signers[0]].PublicKey, verShares, signers)
	require.NoError(t, err)
	return sig
}

// roundTrip marshals v to JSON, unmarshals into a new value of the same type,
// then marshals again and asserts the two JSON outputs are byte-equal.
func roundTrip[T any](t *testing.T, name string, v *T) *T {
	t.Helper()
	b1, err := json.Marshal(v)
	require.NoError(t, err, "%s: first marshal", name)
	require.NotEmpty(t, b1)

	var out T
	err = json.Unmarshal(b1, &out)
	require.NoError(t, err, "%s: unmarshal", name)

	b2, err := json.Marshal(&out)
	require.NoError(t, err, "%s: second marshal", name)
	require.JSONEq(t, string(b1), string(b2), "%s: round-trip JSON mismatch", name)
	return &out
}

// failingEncryptor always returns errors, used to test error paths.
type failingEncryptor struct{}

func (f *failingEncryptor) Encrypt([]byte) ([]byte, error) {
	return nil, errors.New("encrypt failed")
}
func (f *failingEncryptor) Decrypt([]byte) ([]byte, error) {
	return nil, errors.New("decrypt failed")
}

// identityEncryptor returns plaintext as-is, used to test round-trip.
type identityEncryptor struct{}

func (f *identityEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	return plaintext, nil
}
func (f *identityEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	return ciphertext, nil
}
