package dkls23

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/chrisalmeida/go-mpc/session"
	"github.com/chrisalmeida/go-mpc/session/storetest"
	"github.com/stretchr/testify/require"
)

func TestTransactionalSigningRecoversCommittedRoundAndRejectsCopies(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	model := &storetest.Model{}
	setups := fullSetup(t)
	owners := make(map[int]session.Scope)
	versions := make(map[int]session.Version)
	signers := []int{1, 2, 3}
	sigID := t.Name()
	message := []byte("durable DKLS23 round recovery")
	// Private round state lives only in the store's checkpoints; the round-3
	// callback records each party's decoded round-2 state so combine can
	// reconstruct R the same way the in-memory session tests do.
	s := &signingSession{sigID: sigID, signers: signers, r1Msgs: make(map[int]map[int]*Round1Msg), r2States: make(map[int]*Round2State), r2Msgs: make(map[int]map[int]*Round2Msg), r3Frags: make(map[int]map[int]*Round3Msg)}
	for _, id := range signers {
		owners[id] = session.Scope{Protocol: session.DKLS23, PublicKey: string(setups[id].PubKey), PartyID: id}
		checkpoint, err := MarshalSetup(setups[id])
		require.NoError(t, err)
		versions[id], err = session.Initialize(ctx, model.Open(), owners[id], setups[id].Epoch, checkpoint)
		require.NoError(t, err)
	}
	backup := versions[1]
	for round := 1; round <= 3; round++ {
		for _, id := range signers {
			req := session.Request{Version: versions[id], ID: session.ID{Kind: session.Signing, Epoch: versions[id].Epoch, Value: sigID}, Round: round, Participants: signers}
			var computations atomic.Int32
			compute := func(in session.Input) (session.Update, error) {
				computations.Add(1)
				setup, err := UnmarshalSetup(in.KeyCheckpoint)
				if err != nil {
					return session.Update{}, err
				}
				if setup.MyID != in.Scope.PartyID || string(setup.PubKey) != in.Scope.PublicKey || setup.Epoch != in.Epoch {
					return session.Update{}, session.ErrCorrupt
				}
				var private, public any
				nonceID := ""
				switch in.Round {
				case 1:
					state, out, err := SignRound1(setup, in.ID.Value, in.Participants)
					if err != nil {
						return session.Update{}, err
					}
					private, public, nonceID = state, out, string(state.R_iPoint)
				case 2:
					var state Round1State
					if err := json.Unmarshal(in.SessionCheckpoint, &state); err != nil {
						return session.Update{}, err
					}
					next, out, err := SignRound2(setup, &state, s.round1For(id))
					if err != nil {
						return session.Update{}, err
					}
					private, public = next, out
				case 3:
					var state Round2State
					if err := json.Unmarshal(in.SessionCheckpoint, &state); err != nil {
						return session.Update{}, err
					}
					out, err := SignRound3(setup, &state, message, s.round2For(id))
					if err != nil {
						return session.Update{}, err
					}
					s.r2States[id] = &state
					public = out
				}
				var next []byte
				if private != nil {
					next, err = json.Marshal(private)
					if err != nil {
						return session.Update{}, err
					}
				}
				output, err := json.Marshal(public)
				if err != nil {
					return session.Update{}, err
				}
				key, err := MarshalSetup(setup)
				return session.Update{KeyCheckpoint: key, Checkpoint: next, Output: output, NonceID: nonceID}, err
			}
			var output []byte
			if id == 1 && round == 2 {
				model.FailNext(storetest.AfterCommit)
				receipt, err := session.Advance(ctx, model.Open(), owners[id], req, compute)
				require.ErrorIs(t, err, storetest.ErrInjected)
				require.Nil(t, receipt)
				output, err = session.Output(ctx, model.Open(), owners[id], req.ID, round)
				require.NoError(t, err)
			} else if id == 1 {
				type result struct {
					receipt *session.Receipt
					err     error
				}
				results := make(chan result, 8)
				for range 8 {
					go func() {
						r, err := session.Advance(ctx, model.Open(), owners[id], req, compute)
						results <- result{r, err}
					}()
				}
				successes := 0
				for range 8 {
					r := <-results
					if r.err == nil {
						successes++
						output = r.receipt.Output
					} else {
						require.Nil(t, r.receipt)
						require.ErrorIs(t, r.err, session.ErrStale)
					}
				}
				require.Equal(t, 1, successes)
			} else {
				receipt, err := session.Advance(ctx, model.Open(), owners[id], req, compute)
				require.NoError(t, err)
				output = receipt.Output
			}
			require.EqualValues(t, 1, computations.Load())
			key, err := session.InspectKey(ctx, model.Open(), owners[id])
			require.NoError(t, err)
			versions[id] = key.Version
			req.Version = key.Version
			_, err = session.Advance(ctx, model.Open(), owners[id], req, compute)
			require.ErrorIs(t, err, session.ErrProgress)
			require.EqualValues(t, 1, computations.Load(), "replay must not recompute the round")
			switch round {
			case 1:
				var messages map[int]*Round1Msg
				require.NoError(t, json.Unmarshal(output, &messages))
				s.r1Msgs[id] = messages
			case 2:
				var messages map[int]*Round2Msg
				require.NoError(t, json.Unmarshal(output, &messages))
				s.r2Msgs[id] = messages
			case 3:
				var fragments map[int]*Round3Msg
				require.NoError(t, json.Unmarshal(output, &fragments))
				s.r3Frags[id] = fragments
			}
			if round == 3 {
				record, err := session.InspectSession(ctx, model.Open(), owners[id], req.ID)
				require.NoError(t, err)
				require.Empty(t, record.Checkpoint)
				require.Zero(t, key.ActiveSessions)
			}
		}
	}
	r, signature := s.combine(t, setups, message)
	verifyECDSA(t, setups[1].PubKey, message, r, signature)
	_, err := session.Advance(ctx, model.Open(), owners[1], session.Request{Version: backup, ID: session.ID{Kind: session.Signing, Epoch: 0, Value: "from old backup"}, Round: 1, Participants: signers}, func(session.Input) (session.Update, error) { return session.Update{}, fmt.Errorf("must not execute") })
	require.ErrorIs(t, err, session.ErrStale)
}
