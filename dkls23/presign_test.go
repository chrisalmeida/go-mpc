package dkls23

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSignPresignatureCompletesExactlyOneMessage exercises the pre-signing
// arrangement of DKLS23 Section 3.3: rounds 1 and 2 run before any message
// exists, the message is supplied only at round 3, and the result verifies.
// The same presignature must then refuse a second message, because two
// signatures under one nonce would reveal the key. (AUDIT.md FU-LOW-8)
func TestSignPresignatureCompletesExactlyOneMessage(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	signers := []int{1, 2, 3}

	s := runRound1(t, setups, t.Name(), signers)
	runRound2(t, setups, s)
	first := []byte("message chosen after the presignature exists")
	runRound3(t, setups, s, first)
	r, sig := s.combine(t, setups, first)
	verifyECDSA(t, setups[1].PubKey, first, r, sig)

	second := []byte("a second message for the same presignature")
	for _, id := range signers {
		_, err := SignRound3(setups[id], s.r2States[id], second, s.round2For(id))
		var reused *SessionIDReusedError
		require.ErrorAs(t, err, &reused, "party %d must refuse to reuse its presignature", id)
	}
}
