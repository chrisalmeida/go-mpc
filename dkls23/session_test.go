package dkls23

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRejectedImportPreservesSigningSession(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		round int
		field string
		value json.RawMessage
	}{
		{"setup version", 0, "version", json.RawMessage(`99`)},
		{"setup share", 0, "share", json.RawMessage(`"not hex"`)},
		{"setup session stages", 0, "session_ids", json.RawMessage(`{"invalid":0}`)},
		{"round 1 salt", 1, "salt", json.RawMessage(`"not hex"`)},
		{"round 2 commitment map", 2, "round1_commits", json.RawMessage(`{"invalid":"00"}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			setups := fullSetup(t)
			session := runRound1(t, setups, t.Name(), []int{1, 2, 3})
			var target any = setups[1]
			switch tc.round {
			case 1:
				target = session.r1States[1]
			case 2:
				runRound2(t, setups, session)
				target = session.r2States[1]
			}
			before, err := json.Marshal(target)
			require.NoError(t, err)
			var fields map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(before, &fields))
			fields[tc.field] = tc.value
			replacement, err := json.Marshal(fields)
			require.NoError(t, err)
			require.Error(t, json.Unmarshal(replacement, target))
			after, err := json.Marshal(target)
			require.NoError(t, err)
			require.Equal(t, before, after)

			// Serialized equality alone misses changes to private lifetime guards.
			// Finish the original operation and verify its cryptographic result.
			if tc.round != 2 {
				runRound2(t, setups, session)
			}
			message := []byte("continue after a rejected import")
			runRound3(t, setups, session, message)
			r, signature := session.combine(t, setups, message)
			verifyECDSA(t, setups[1].PubKey, message, r, signature)
		})
	}
}

func TestSignResumesWithRestoredSetup(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	s := runRound1(t, setups, t.Name(), []int{1, 2, 3})
	for _, id := range []int{1, 2, 3} {
		setups[id] = roundTrip(t, "SignerSetup", setups[id])
	}
	msg := []byte("continue with a restored setup")
	runRound2(t, setups, s)
	runRound3(t, setups, s, msg)
	r, sig := s.combine(t, setups, msg)
	verifyECDSA(t, setups[1].PubKey, msg, r, sig)
}

func TestSignResumesWithRestoredRoundState(t *testing.T) {
	t.Parallel()
	for _, round := range []int{1, 2} {
		t.Run(fmt.Sprintf("round %d", round), func(t *testing.T) {
			t.Parallel()
			setups := fullSetup(t)
			s := runRound1(t, setups, t.Name(), []int{1, 2, 3})
			if round == 2 {
				runRound2(t, setups, s)
			}
			for _, id := range []int{1, 2, 3} {
				setups[id] = roundTrip(t, "SignerSetup", setups[id])
				if round == 1 {
					s.r1States[id] = roundTrip(t, "Round1State", s.r1States[id])
				} else {
					s.r2States[id] = roundTrip(t, "Round2State", s.r2States[id])
				}
			}
			if round == 1 {
				runRound2(t, setups, s)
			}
			msg := []byte("continue with restored private round state")
			runRound3(t, setups, s, msg)
			r, sig := s.combine(t, setups, msg)
			verifyECDSA(t, setups[1].PubKey, msg, r, sig)
		})
	}
}

func TestSignResumesAfterInPlaceRestore(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	s := runRound1(t, setups, t.Name(), []int{1, 2, 3})
	for _, target := range []any{setups[1], s.r1States[1]} {
		snapshot, err := json.Marshal(target)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(snapshot, target))
	}
	msg := []byte("continue after in-place restoration")
	runRound2(t, setups, s)
	runRound3(t, setups, s, msg)
	r, sig := s.combine(t, setups, msg)
	verifyECDSA(t, setups[1].PubKey, msg, r, sig)
}
