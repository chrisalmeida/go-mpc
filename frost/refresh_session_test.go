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

func TestRejectedImportPreservesPendingRefresh(t *testing.T) {
	t.Parallel()
	setups := makeSignerStates(fullSetup(t))
	ids := []int{1, 2, 3}
	r1 := make(map[int]*RefreshRound1Output)
	r2 := make(map[int]*RefreshRound2Output)
	coeffs := make(map[int][]*edwards25519.Scalar)
	seeds := make(map[int][16]byte)
	for _, id := range ids {
		out, cs, seed, err := RefreshRound1(setups[id])
		require.NoError(t, err)
		r1[id], coeffs[id], seeds[id] = out, cs, seed
	}
	require.Error(t, json.Unmarshal([]byte(`{"version":99}`), setups[1]))
	for _, id := range ids {
		out, err := RefreshRound2(setups[id], coeffs[id], seeds[id])
		require.NoError(t, err)
		r2[id] = out
	}
	for _, id := range ids {
		require.NoError(t, RefreshFinalize(setups[id], coeffs[id], seeds[id], r1, r2))
		require.Equal(t, 1, setups[id].Epoch)
	}
	message := []byte("refresh survives a rejected import")
	signature := fullSignWithStates(t, setups, ids, message)
	require.True(t, ed25519.Verify(setups[1].KeyShare.PublicKey, message, signature.Bytes()))
}

func TestRefreshFinalizeIsSingleUse(t *testing.T) {
	t.Parallel()
	setups := makeSignerStates(fullSetup(t))
	ids := []int{1, 2, 3}
	r1 := make(map[int]*RefreshRound1Output)
	r2 := make(map[int]*RefreshRound2Output)
	coeffs := make(map[int][]*edwards25519.Scalar)
	seeds := make(map[int][16]byte)
	for _, id := range ids {
		out, cs, seed, err := RefreshRound1(setups[id])
		require.NoError(t, err)
		r1[id], coeffs[id], seeds[id] = out, cs, seed
	}
	for _, id := range ids {
		out, err := RefreshRound2(setups[id], coeffs[id], seeds[id])
		require.NoError(t, err)
		r2[id] = out
	}
	const workers = 8
	start := make(chan struct{})
	results := make(chan error, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- RefreshFinalize(setups[1], coeffs[1], seeds[1], r1, r2)
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else {
			var corrupt *CorruptStateError
			require.ErrorAs(t, err, &corrupt)
		}
	}
	require.Equal(t, 1, successes)
	require.Equal(t, 1, setups[1].Epoch)
	var replay *CorruptStateError
	require.ErrorAs(t, RefreshFinalize(setups[1], coeffs[1], seeds[1], r1, r2), &replay)
	require.Equal(t, 1, setups[1].Epoch, "sequential replay must not advance the epoch")
	for _, id := range []int{2, 3} {
		require.NoError(t, RefreshFinalize(setups[id], coeffs[id], seeds[id], r1, r2))
	}
	// The one accepted update must leave the group able to sign, not merely
	// prevent subsequent calls from returning nil.
	msg := []byte("sign after one refresh application")
	sig := fullSignWithStates(t, setups, []int{1, 2, 3}, msg)
	require.True(t, ed25519.Verify(setups[1].KeyShare.PublicKey, msg, sig.Bytes()))
	// An older completed contribution must remain spent after another refresh.
	runRefresh(t, setups)
	before := setups[1].Epoch
	err := RefreshFinalize(setups[1], coeffs[1], seeds[1], r1, r2)
	var corrupt *CorruptStateError
	require.ErrorAs(t, err, &corrupt)
	require.Equal(t, before, setups[1].Epoch)
}

func TestRefreshPreservesPendingContribution(t *testing.T) {
	t.Parallel()
	for _, round := range []int{0, 1, 2} {
		name := fmt.Sprintf("restore after round %d", round)
		if round == 0 {
			name = "another round 1"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			setups := makeSignerStates(fullSetup(t))
			ids := []int{1, 2, 3}
			r1 := make(map[int]*RefreshRound1Output)
			r2 := make(map[int]*RefreshRound2Output)
			coeffs := make(map[int][]*edwards25519.Scalar)
			seeds := make(map[int][16]byte)
			for _, id := range ids {
				out, cs, seed, err := RefreshRound1(setups[id])
				require.NoError(t, err)
				r1[id], coeffs[id], seeds[id] = out, cs, seed
			}
			if round == 0 {
				// A second round-1 call must not retire an earlier contribution.
				_, _, _, err := RefreshRound1(setups[1])
				require.NoError(t, err)
			}
			if round == 1 {
				for _, id := range ids {
					setups[id] = roundTrip(t, "SignerState", setups[id])
				}
			}
			for _, id := range ids {
				out, err := RefreshRound2(setups[id], coeffs[id], seeds[id])
				require.NoError(t, err)
				r2[id] = out
			}
			if round == 2 {
				for _, id := range ids {
					setups[id] = roundTrip(t, "SignerState", setups[id])
				}
			}
			for _, id := range ids {
				require.NoError(t, RefreshFinalize(setups[id], coeffs[id], seeds[id], r1, r2))
				require.Equal(t, 1, setups[id].Epoch)
			}
			message := []byte("existing refresh contribution remains usable")
			signature := fullSignWithStates(t, setups, ids, message)
			require.True(t, ed25519.Verify(setups[1].KeyShare.PublicKey, message, signature.Bytes()))
		})
	}
}
