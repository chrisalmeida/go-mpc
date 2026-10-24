package dkls23

import (
	"context"
	"encoding/json"
	"github.com/btcsuite/btcd/btcec/v2"
	"sync/atomic"
	"testing"

	"github.com/chrisalmeida/go-mpc/session"
	"github.com/chrisalmeida/go-mpc/session/storetest"
	"github.com/stretchr/testify/require"
)

func TestEncryptedSessionCodecSigningRefreshAndRestart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	model := &storetest.Model{}
	enc := newTestEncryptor()
	states := fullSetup(t)
	parties := []int{1, 2, 3}
	owners := make(map[int]session.Scope)
	for _, id := range parties {
		owners[id] = session.Scope{Protocol: session.DKLS23, PublicKey: string(states[id].PubKey), PartyID: id}
		cp, err := MarshalEncrypted(states[id], enc)
		require.NoError(t, err)
		_, err = session.Initialize(ctx, model.Open(), owners[id], 0, cp)
		require.NoError(t, err)
	}
	advanceCipher := func(id int, kind session.Kind, operation string, round int, compute session.Compute) []byte {
		t.Helper()
		key, err := session.InspectKey(ctx, model.Open(), owners[id])
		require.NoError(t, err)
		req := session.Request{Version: key.Version, ID: session.ID{Kind: kind, Epoch: key.Epoch, Value: operation}, Round: round, Participants: parties}
		if id == 1 {
			var calls atomic.Int32
			wrapped := func(in session.Input) (session.Update, error) { calls.Add(1); return compute(in) }
			type result struct {
				r *session.Receipt
				e error
			}
			results := make(chan result, 4)
			for range 4 {
				go func() { r, e := session.Advance(ctx, model.Open(), owners[id], req, wrapped); results <- result{r, e} }()
			}
			var output []byte
			successes := 0
			for range 4 {
				result := <-results
				if result.e == nil {
					successes++
					output = result.r.Output
				} else {
					require.ErrorIs(t, result.e, session.ErrStale)
					require.Nil(t, result.r)
				}
			}
			require.Equal(t, 1, successes)
			require.EqualValues(t, 1, calls.Load())
			req.Revision++
			_, err = session.Advance(ctx, model.Open(), owners[id], req, compute)
			require.ErrorIs(t, err, session.ErrProgress)
			return output
		}
		if id == 2 && round == 1 {
			model.FailNext(storetest.AfterCommit)
			r, err := session.Advance(ctx, model.Open(), owners[id], req, compute)
			require.ErrorIs(t, err, storetest.ErrInjected)
			require.Nil(t, r)
			output, err := session.Output(ctx, model.Open(), owners[id], req.ID, round)
			require.NoError(t, err)
			return output
		}
		r, err := session.Advance(ctx, model.Open(), owners[id], req, compute)
		require.NoError(t, err)
		return r.Output
	}
	advance := func(id int, kind session.Kind, operation string, round int, compute session.Compute) []byte {
		t.Helper()
		blob := advanceCipher(id, kind, operation, round, compute)
		if kind == session.Signing || round == 1 {
			plain, err := (SessionCodec{enc}).OpenOutput(blob, states[id].Binding(), session.ID{Kind: kind, Epoch: states[id].Epoch, Value: operation}, round)
			require.NoError(t, err)
			return plain
		}
		return blob
	}

	sign := func(operation string) {
		r1 := make(map[int]map[int]*Round1Msg)
		r2 := make(map[int]map[int]*Round2Msg)
		r3 := make(map[int]map[int]*Round3Msg)
		msg := []byte("encrypted checkpoints across restart " + operation)
		for _, id := range parties {
			var out map[int]*Round1Msg
			require.NoError(t, json.Unmarshal(advance(id, session.Signing, operation, 1, (SessionCodec{enc}).Signing(SessionSignInput{})), &out))
			r1[id] = out
		}
		for _, id := range parties {
			var out map[int]*Round2Msg
			in := make(map[int]*Round1Msg)
			for _, peer := range parties {
				if peer != id {
					in[peer] = r1[peer][id]
				}
			}
			require.NoError(t, json.Unmarshal(advance(id, session.Signing, operation, 2, (SessionCodec{enc}).Signing(SessionSignInput{Round1: in, Message: msg})), &out))
			r2[id] = out
		}
		for _, id := range parties {
			var out map[int]*Round3Msg
			in := make(map[int]*Round2Msg)
			for _, peer := range parties {
				if peer != id {
					in[peer] = r2[peer][id]
				}
			}
			require.NoError(t, json.Unmarshal(advance(id, session.Signing, operation, 3, (SessionCodec{enc}).Signing(SessionSignInput{Round2: in, Message: msg})), &out))
			r3[id] = out
			record, err := session.InspectSession(ctx, model.Open(), owners[id], session.ID{Kind: session.Signing, Epoch: states[id].Epoch, Value: operation})
			require.NoError(t, err)
			require.True(t, record.Completed)
			require.Empty(t, record.Checkpoint)
		}
		points := make(map[int][]byte)
		fragments := make(map[int]*Round3Msg)
		for _, id := range parties {
			for _, out := range r2[id] {
				points[id] = out.Decommitment
				break
			}
			fragments[id] = r3[id][1]
		}
		rx, err := ComputeRx(points)
		require.NoError(t, err)
		var w, u btcec.ModNScalar
		w.SetByteSlice(fragments[1].W_i)
		u.SetByteSlice(fragments[1].U_i)
		r, ss, err := SignCombine(states[1], &rx, &w, &u, fragments, msg)
		require.NoError(t, err)
		verifyECDSA(t, states[1].PubKey, msg, r, ss)
	}
	sign("before-refresh\x00\xff")
	// Precomputed commitments are ordinary open operations and block refresh.
	advance(1, session.Signing, "unused-commitment", 1, (SessionCodec{enc}).Signing(SessionSignInput{}))
	key, err := session.InspectKey(ctx, model.Open(), owners[1])
	require.NoError(t, err)
	_, err = session.Advance(ctx, model.Open(), owners[1], session.Request{Version: key.Version, ID: session.ID{Kind: session.Refresh, Value: "refresh"}, Round: 1, Participants: parties}, (SessionCodec{enc}).Refresh(nil, nil))
	require.ErrorIs(t, err, session.ErrBusy)
	_, err = session.Abort(ctx, model.Open(), owners[1], key.Version, session.ID{Kind: session.Signing, Value: "unused-commitment"})
	require.NoError(t, err)
	r1 := make(map[int]*RefreshRound1Output)
	r2 := make(map[int]*RefreshRound2Output)
	for _, id := range parties {
		var out RefreshRound1Output
		require.NoError(t, json.Unmarshal(advance(id, session.Refresh, "refresh", 1, (SessionCodec{enc}).Refresh(nil, nil)), &out))
		r1[id] = &out
	}
	for _, id := range parties {
		blob := advance(id, session.Refresh, "refresh", 2, (SessionCodec{enc}).Refresh(r1, nil))
		out, err := (SessionCodec{enc}).OpenRefreshRound2(blob, states[id].Binding(), "refresh")
		require.NoError(t, err)
		r2[id] = out
		record, err := session.InspectSession(ctx, model.Open(), owners[id], session.ID{Kind: session.Refresh, Value: "refresh"})
		require.NoError(t, err)
		require.Equal(t, blob, record.Outputs[2])
	}

	for _, id := range parties {
		require.Empty(t, advance(id, session.Refresh, "refresh", 3, (SessionCodec{enc}).Refresh(r1, r2)))
	}
	for _, id := range parties {
		key, err := session.InspectKey(ctx, model.Open(), owners[id])
		require.NoError(t, err)
		require.Equal(t, 0, key.Epoch)
		require.True(t, key.Refresh.Prepared)
		v, err := session.Activate(ctx, model.Open(), owners[id], key.Version, "refresh")
		require.NoError(t, err)
		key, err = session.InspectKey(ctx, model.Open(), owners[id])
		require.NoError(t, err)
		restored, err := UnmarshalEncrypted(key.Checkpoint, enc, KeyBinding{PublicKey: []byte(owners[id].PublicKey), PartyID: id, Epoch: v.Epoch})
		require.NoError(t, err)
		require.Equal(t, 1, restored.Epoch)
		require.False(t, states[id].Share.Equals(&restored.Share))
		states[id] = restored
	}
	sign("after-refresh")
}
