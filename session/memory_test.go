package session_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/chrisalmeida/go-mpc/session"
	"github.com/chrisalmeida/go-mpc/session/storetest"
	"github.com/stretchr/testify/require"
)

func TestMemoryModeClearsSupersededCheckpointsOnlyAfterConfirmedCommit(t *testing.T) {
	t.Parallel()
	for _, failure := range []storetest.Failure{0, storetest.BeforeCommit, storetest.AfterCommit} {
		t.Run(fmt.Sprint(failure), func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			model := &storetest.Model{}
			owner := scope(session.DKLS23)
			otherOwner := owner
			otherOwner.PartyID = 2
			initialize(t, model, otherOwner)
			v := initialize(t, model, owner)
			memory := &session.Memory{}
			defer memory.Close()
			advance := func(owner session.Scope, name string, round int) *session.Receipt {
				t.Helper()
				key, err := session.InspectKey(ctx, model.Open(), owner)
				require.NoError(t, err)
				r, err := memory.Advance(ctx, model.Open(), owner, request(key.Version, session.Signing, name, round), func(in session.Input) (session.Update, error) {
					if in.Round > 1 {
						require.Equal(t, []byte(fmt.Sprintf("private round %d", in.Round-1)), in.SessionCheckpoint)
					}
					return update(in)
				})
				require.NoError(t, err)
				return r
			}
			// Keep another operation and another scope live to catch overbroad cleanup.
			advance(owner, "another", 1)
			advance(otherOwner, "sign", 1)
			id := request(v, session.Signing, "sign", 1).ID
			otherID := request(v, session.Signing, "another", 1).ID
			otherOperation := session.MemoryCheckpointsForTest(memory, owner, otherID)[1]
			otherScope := session.MemoryCheckpointsForTest(memory, otherOwner, id)[1]
			r := advance(owner, "sign", 1)
			first := session.MemoryCheckpointsForTest(memory, owner, id)[1]
			require.Equal(t, []byte("private round 1"), first)
			req := request(r.Version, session.Signing, "sign", 2)
			var uncertain []byte
			if failure != 0 {
				model.FailNext(failure)
				result, err := memory.Advance(ctx, model.Open(), owner, req, update)
				require.ErrorIs(t, err, storetest.ErrInjected)
				require.Nil(t, result)
				retained := session.MemoryCheckpointsForTest(memory, owner, id)
				require.Len(t, retained, 2)
				require.Equal(t, []byte("private round 1"), first)
				uncertain = retained[2]
				require.Equal(t, []byte("private round 2"), uncertain)
			}
			if failure != storetest.AfterCommit {
				advance(owner, "sign", 2)
				retained := session.MemoryCheckpointsForTest(memory, owner, id)
				require.Len(t, retained, 1)
				require.NotContains(t, retained, 1)
				require.Equal(t, make([]byte, len(first)), first)
				require.Equal(t, []byte("private round 2"), retained[2])
				if uncertain != nil {
					require.Equal(t, make([]byte, len(uncertain)), uncertain)
				}
			}
			second := session.MemoryCheckpointsForTest(memory, owner, id)[2]
			r = advance(owner, "sign", 3)
			require.Equal(t, []byte("output sign 3"), r.Output)
			require.Empty(t, session.MemoryCheckpointsForTest(memory, owner, id))
			require.Equal(t, make([]byte, len(first)), first)
			require.Equal(t, make([]byte, len(second)), second)
			require.Equal(t, []byte("private round 1"), otherOperation)
			require.Equal(t, []byte("private round 1"), otherScope)
		})
	}
}

func TestMemoryModeNeverStoresPrivateRoundStateAndRequiresAbortAfterLoss(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	model := &storetest.Model{}
	owner := scope(session.FROST)
	v := initialize(t, model, owner)
	memory := &session.Memory{}
	req := request(v, session.Signing, "sign", 1)
	r, err := memory.Advance(ctx, model.Open(), owner, req, update)
	require.NoError(t, err)
	record, err := session.InspectSession(ctx, model.Open(), owner, req.ID)
	require.NoError(t, err)
	require.Empty(t, record.Checkpoint)
	require.Equal(t, session.InMemory, record.Mode)
	req.Version = r.Version
	req.Round = 2
	other := &session.Memory{}
	_, err = other.Advance(ctx, model.Open(), owner, req, update)
	require.ErrorIs(t, err, session.ErrUnavailable)
	req.Mode = session.Resumable
	_, err = session.Advance(ctx, model.Open(), owner, req, update)
	require.ErrorIs(t, err, session.ErrInvalid)
	memory.Close()
	_, err = memory.Advance(ctx, model.Open(), owner, req, update)
	require.ErrorIs(t, err, session.ErrUnavailable)
	v, err = session.Abort(ctx, model.Open(), owner, req.Version, req.ID)
	require.NoError(t, err)
	memory.Forget(owner, req.ID)
	_, err = memory.Advance(ctx, model.Open(), owner, request(v, session.Signing, "sign", 1), update)
	require.ErrorIs(t, err, session.ErrAborted)
	req = request(v, session.Signing, "new", 1)
	r, err = memory.Advance(ctx, model.Open(), owner, req, update)
	require.NoError(t, err)
	req.Version = r.Version
	req.Round = 2
	r, err = memory.Advance(ctx, model.Open(), owner, req, func(in session.Input) (session.Update, error) {
		require.Equal(t, []byte("private round 1"), in.SessionCheckpoint)
		return update(in)
	})
	require.NoError(t, err)
	require.NotEmpty(t, r.Output)
	record, err = session.InspectSession(ctx, model.Open(), owner, req.ID)
	require.NoError(t, err)
	require.True(t, record.Completed)
	require.Empty(t, record.Checkpoint)
}

func TestMemoryModeCommitFailureRetainsOnlyAuthoritativeRound(t *testing.T) {
	t.Parallel()
	for _, failure := range []storetest.Failure{storetest.BeforeCommit, storetest.AfterCommit} {
		t.Run(string(rune('0'+failure)), func(t *testing.T) {
			ctx := context.Background()
			model := &storetest.Model{}
			owner := scope(session.DKLS23)
			v := initialize(t, model, owner)
			memory := &session.Memory{}
			defer memory.Close()
			req := request(v, session.Signing, "sign", 1)
			model.FailNext(failure)
			r, err := memory.Advance(ctx, model.Open(), owner, req, update)
			require.ErrorIs(t, err, storetest.ErrInjected)
			require.Nil(t, r)
			if failure == storetest.BeforeCommit {
				_, err = memory.Advance(ctx, model.Open(), owner, req, update)
				require.NoError(t, err)
			}
			key, err := session.InspectKey(ctx, model.Open(), owner)
			require.NoError(t, err)
			req.Version = key.Version
			req.Round = 2
			r, err = memory.Advance(ctx, model.Open(), owner, req, func(in session.Input) (session.Update, error) {
				require.Equal(t, []byte("private round 1"), in.SessionCheckpoint)
				return update(in)
			})
			require.NoError(t, err)
			req.Version = r.Version
			req.Round = 3
			r, err = memory.Advance(ctx, model.Open(), owner, req, func(in session.Input) (session.Update, error) {
				require.Equal(t, []byte("private round 2"), in.SessionCheckpoint)
				return update(in)
			})
			require.NoError(t, err)
			require.NotEmpty(t, r.Output)
		})
	}
}

func TestMemoryModeRejectsInvalidUpdatesAndPreservesProgress(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	model := &storetest.Model{}
	owner := scope(session.FROST)
	v := initialize(t, model, owner)
	req := request(v, session.Signing, "sign", 1)
	var nilMemory *session.Memory
	_, err := nilMemory.Advance(ctx, model.Open(), owner, req, update)
	require.ErrorIs(t, err, session.ErrInvalid)
	memory := &session.Memory{}
	defer memory.Close()
	_, err = memory.Advance(ctx, model.Open(), owner, req, nil)
	require.ErrorIs(t, err, session.ErrInvalid)
	_, err = memory.Advance(ctx, model.Open(), owner, req, func(session.Input) (session.Update, error) { return session.Update{}, errors.New("compute") })
	require.Error(t, err)
	_, err = memory.Advance(ctx, model.Open(), owner, req, func(in session.Input) (session.Update, error) { u, e := update(in); u.Checkpoint = nil; return u, e })
	require.ErrorIs(t, err, session.ErrInvalid)
	_, err = memory.Advance(ctx, model.Open(), owner, req, func(in session.Input) (session.Update, error) {
		u, e := update(in)
		u.Output = nil
		u.NonceID = ""
		u.Abort = errors.New("abort with private state")
		return u, e
	})
	require.ErrorIs(t, err, session.ErrInvalid)
	req.Mode = "unknown"
	_, err = session.Advance(ctx, model.Open(), owner, req, update)
	require.ErrorIs(t, err, session.ErrInvalid)
	req.Mode = session.InMemory
	_, err = session.Advance(ctx, model.Open(), owner, req, update)
	require.ErrorIs(t, err, session.ErrInvalid)
	_, err = memory.Advance(ctx, model.Open(), owner, req, func(in session.Input) (session.Update, error) {
		u, e := update(in)
		u.Checkpoint = nil
		u.Output = nil
		u.NonceID = ""
		u.Abort = errors.New("terminal abort")
		return u, e
	})
	require.ErrorContains(t, err, "terminal abort")
	memory.Forget(owner, req.ID)
}

func TestNonceMarkersAreDigestsAndLegacyReservationsStillReject(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, legacy := range []bool{false, true} {
		model := &storetest.Model{}
		owner := scope(session.FROST)
		v := initialize(t, model, owner)
		raw := strings.Repeat("s", 64)
		marker := session.NonceMarker([]byte(raw))
		require.Len(t, marker, 32)
		if legacy {
			write(t, model, owner, func(tx session.Transaction) error { return tx.UseNonce(raw) })
		}
		r, err := session.Advance(ctx, model.Open(), owner, request(v, session.Signing, "sign", 1), update)
		if legacy {
			require.ErrorIs(t, err, session.ErrNonceUsed)
			require.Nil(t, r)
		} else {
			require.NoError(t, err)
			write(t, model, owner, func(tx session.Transaction) error {
				used, err := tx.NonceUsed(raw)
				require.False(t, used)
				require.NoError(t, err)
				used, err = tx.NonceUsed(marker)
				require.True(t, used)
				return err
			})
		}
	}
}
