package dkls23

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// Protocol 3.6 step 4 and the persisted round-progress guard apply to every
// signing round. Competing calls must release one output, including under
// -race, and the winning outputs must still form a valid ECDSA signature.
func TestSignSessionRoundsAreSingleUseConcurrent(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	s := &signingSession{
		sigID: t.Name(), signers: []int{1, 2, 3},
		r1States: make(map[int]*Round1State), r1Msgs: make(map[int]map[int]*Round1Msg),
		r2States: make(map[int]*Round2State), r2Msgs: make(map[int]map[int]*Round2Msg),
		r3Frags: make(map[int]map[int]*Round3Msg),
	}
	message := []byte("one successful output per round")
	type result struct {
		r1  *Round1State
		m1  map[int]*Round1Msg
		r2  *Round2State
		m2  map[int]*Round2Msg
		m3  map[int]*Round3Msg
		err error
	}
	for round := 1; round <= 3; round++ {
		call := func(id int) (out result) {
			switch round {
			case 1:
				out.r1, out.m1, out.err = SignRound1(setups[id], s.sigID, s.signers)
			case 2:
				out.r2, out.m2, out.err = SignRound2(setups[id], s.r1States[id], s.round1For(id))
			case 3:
				out.m3, out.err = SignRound3(setups[id], s.r2States[id], message, s.round2For(id))
			}
			return
		}
		store := func(id int, out result) {
			switch round {
			case 1:
				s.r1States[id], s.r1Msgs[id] = out.r1, out.m1
			case 2:
				s.r2States[id], s.r2Msgs[id] = out.r2, out.m2
			case 3:
				s.r3Frags[id] = out.m3
			}
		}
		const workers = 8
		start := make(chan struct{})
		results := make(chan result, workers)
		for range workers {
			go func() { <-start; results <- call(1) }()
		}
		close(start)
		successes := 0
		var winner result
		for range workers {
			out := <-results
			if out.err == nil {
				successes++
				winner = out
			} else {
				var reused *SessionIDReusedError
				require.ErrorAs(t, out.err, &reused)
				require.Nil(t, out.r1)
				require.Nil(t, out.r2)
				require.Nil(t, out.m1)
				require.Nil(t, out.m2)
				require.Nil(t, out.m3)
			}
		}
		require.Equal(t, 1, successes, "round %d", round)
		store(1, winner)
		var reused *SessionIDReusedError
		require.ErrorAs(t, call(1).err, &reused, "sequential replay of round %d", round)
		for _, id := range []int{2, 3} {
			out := call(id)
			require.NoError(t, out.err)
			store(id, out)
		}
	}
	r, signature := s.combine(t, setups, message)
	verifyECDSA(t, setups[1].PubKey, message, r, signature)
}

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
