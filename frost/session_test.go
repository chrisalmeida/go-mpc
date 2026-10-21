package frost

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/require"
)

func sessionFixture(t *testing.T) (map[int]*SignerState, map[int]*Round1State, map[int]*NonceCommitment) {
	t.Helper()
	signers := makeSignerStates(fullSetup(t))
	states := make(map[int]*Round1State)
	commitments := make(map[int]*NonceCommitment)
	for _, id := range []int{1, 2, 3} {
		state, commitment, err := SignRound1(signers[id], []int{1, 2, 3})
		require.NoError(t, err)
		states[id], commitments[id] = state, commitment
	}
	return signers, states, commitments
}

func finishNonceSession(t *testing.T, signers map[int]*SignerState, states map[int]*Round1State, commitments map[int]*NonceCommitment, message []byte) {
	t.Helper()
	shares := make(map[int]*SignatureShare)
	verification := make(map[int][]byte)
	for _, id := range []int{1, 2, 3} {
		share, err := SignRound2(signers[id], states[id], &Round2Input{Message: message, AllCommitments: commitments})
		require.NoError(t, err)
		shares[id] = share
		verification[id] = signers[id].KeyShare.VerificationShare
	}
	signature, err := Aggregate(commitments, shares, message, signers[1].KeyShare.PublicKey, verification, []int{1, 2, 3})
	require.NoError(t, err)
	require.True(t, ed25519.Verify(signers[1].KeyShare.PublicKey, message, signature.Bytes()))
}

func TestRejectedImportPreservesSigningSession(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		field string
		value json.RawMessage
	}{
		{"version", "version", json.RawMessage(`99`)},
		{"key share", "key_share", json.RawMessage(`{"version":1,"secret_share":"not hex"}`)},
		{"blacklist", "blacklist", json.RawMessage(`{"invalid":true}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			signers, states, commitments := sessionFixture(t)
			before, err := json.Marshal(signers[1])
			require.NoError(t, err)
			var fields map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(before, &fields))
			fields[tc.field] = tc.value
			if tc.field == "blacklist" {
				// A valid replacement key is decoded before the invalid blacklist.
				// The rejected load must not publish that earlier field either.
				var keyFields map[string]json.RawMessage
				require.NoError(t, json.Unmarshal(fields["key_share"], &keyFields))
				keyFields["id"] = json.RawMessage(`7`)
				fields["key_share"], err = json.Marshal(keyFields)
				require.NoError(t, err)
			}
			replacement, err := json.Marshal(fields)
			require.NoError(t, err)
			require.Error(t, json.Unmarshal(replacement, signers[1]))
			after, err := json.Marshal(signers[1])
			require.NoError(t, err)
			require.Equal(t, before, after)

			finishNonceSession(t, signers, states, commitments, []byte("continue after a rejected import"))
		})
	}
}

// RFC 9591 Sections 5.1-5.2: a nonce pair is input to sign at most once.
// The winning share must still aggregate to a valid, independently verified
// signature; merely counting errors would miss nonce-zeroization races.
func TestSignConcurrentNonceConsumption(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name           string
		copied         bool
		restoredSigner bool
	}{
		{"original", false, false},
		{"copied", true, false},
		{"restored signers", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			signers, states, commitments := sessionFixture(t)
			const workers = 16
			type result struct {
				share *SignatureShare
				msg   []byte
				err   error
			}
			start := make(chan struct{})
			results := make(chan result, workers)
			var wg sync.WaitGroup
			for i := range workers {
				state := states[1]
				if tc.copied {
					copyOfState := *state
					state = &copyOfState
				}
				signer := signers[1]
				if tc.restoredSigner {
					signer = roundTrip(t, "SignerState", signer)
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					msg := []byte(fmt.Sprintf("concurrent request %d", i))
					share, err := SignRound2(signer, state, &Round2Input{Message: msg, AllCommitments: commitments})
					results <- result{share, msg, err}
				}()
			}
			close(start)
			wg.Wait()
			close(results)
			var winner result
			successes := 0
			for r := range results {
				if r.err == nil {
					successes++
					winner = r
				} else {
					var corrupt *CorruptStateError
					require.ErrorAs(t, r.err, &corrupt)
					require.Nil(t, r.share)
				}
			}
			require.Equal(t, 1, successes)
			require.Equal(t, 1, states[1].HidingNonce.Equal(edwards25519.NewScalar()))
			require.Equal(t, 1, states[1].BindingNonce.Equal(edwards25519.NewScalar()))
			shares := map[int]*SignatureShare{1: winner.share}
			verification := make(map[int][]byte)
			for _, id := range []int{1, 2, 3} {
				verification[id] = signers[id].KeyShare.VerificationShare
				if id != 1 {
					share, err := SignRound2(signers[id], states[id], &Round2Input{Message: winner.msg, AllCommitments: commitments})
					require.NoError(t, err)
					shares[id] = share
				}
			}
			sig, err := Aggregate(commitments, shares, winner.msg, signers[1].KeyShare.PublicKey, verification, []int{1, 2, 3})
			require.NoError(t, err)
			require.True(t, ed25519.Verify(signers[1].KeyShare.PublicKey, winner.msg, sig.Bytes()))
		})
	}
}

func TestSignCopiedNonceStateIsSingleUse(t *testing.T) {
	t.Parallel()
	signers, states, commitments := sessionFixture(t)
	copied := *states[1]
	input := &Round2Input{Message: []byte("one invocation"), AllCommitments: commitments}
	_, err := SignRound2(signers[1], states[1], input)
	require.NoError(t, err)
	share, err := SignRound2(signers[1], &copied, input)
	var corrupt *CorruptStateError
	require.ErrorAs(t, err, &corrupt)
	require.Nil(t, share)
}

func TestSignRejectsNonceStateFromAnotherSigner(t *testing.T) {
	t.Parallel()
	signers, states, commitments := sessionFixture(t)
	input := &Round2Input{Message: []byte("wrong signer"), AllCommitments: commitments}
	share, err := SignRound2(signers[2], states[1], input)
	var corrupt *CorruptStateError
	require.ErrorAs(t, err, &corrupt)
	require.Nil(t, share)
	finishNonceSession(t, signers, states, commitments, input.Message)
}

func TestSignResumesWithRestoredSigner(t *testing.T) {
	t.Parallel()
	signers, states, commitments := sessionFixture(t)
	for _, id := range []int{1, 2, 3} {
		signers[id] = roundTrip(t, "SignerState", signers[id])
	}
	finishNonceSession(t, signers, states, commitments, []byte("continue with restored signers"))
}

func TestSignRejectsNonceStateAfterRefresh(t *testing.T) {
	t.Parallel()
	signers, states, commitments := sessionFixture(t)
	runRefresh(t, signers)
	share, err := SignRound2(signers[1], states[1], &Round2Input{Message: []byte("stale"), AllCommitments: commitments})
	var corrupt *CorruptStateError
	require.ErrorAs(t, err, &corrupt)
	require.Nil(t, share)
	msg := []byte("fresh round 1 after refresh")
	sig := fullSignWithStates(t, signers, []int{1, 2, 3}, msg)
	require.True(t, ed25519.Verify(signers[1].KeyShare.PublicKey, msg, sig.Bytes()))
}

func TestSignRound1OwnsParticipantAndCommitmentCopies(t *testing.T) {
	t.Parallel()
	signer := NewSignerState(fullSetup(t)[1])
	ids := []int{1, 2, 3}
	state, commitment, err := SignRound1(signer, ids)
	require.NoError(t, err)
	ids[0] = 99
	commitment.HidingNonceCommitment[0] ^= 1
	commitment.BindingNonceCommitment[0] ^= 1
	require.Equal(t, []int{1, 2, 3}, state.Signers)
	actual := commitNonces(state.HidingNonce, state.BindingNonce)
	require.Equal(t, actual, state.Commitment)
}

func TestSignResumesAfterInPlaceRestore(t *testing.T) {
	t.Parallel()
	signers, states, commitments := sessionFixture(t)
	snapshot, err := json.Marshal(signers[1])
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(snapshot, signers[1]))
	finishNonceSession(t, signers, states, commitments, []byte("continue after in-place restoration"))
}

func TestSignRejectsErasedManuallySuppliedNonceCopy(t *testing.T) {
	t.Parallel()
	signers, states, commitments := sessionFixture(t)
	// RFC vector fixtures supply raw nonce pairs. Even without the constructor's
	// shared lifetime guard, a stale alias must not sign using erased nonces.
	states[1].use = nil
	copied := *states[1]
	input := &Round2Input{Message: []byte("raw nonce fixture"), AllCommitments: commitments}
	_, err := SignRound2(signers[1], states[1], input)
	require.NoError(t, err)
	share, err := SignRound2(signers[1], &copied, input)
	var corrupt *CorruptStateError
	require.ErrorAs(t, err, &corrupt)
	require.Nil(t, share)
}
