package session_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/chrisalmeida/go-mpc/session"
	"github.com/chrisalmeida/go-mpc/session/storetest"
	"github.com/stretchr/testify/require"
)

func scope(protocol session.Protocol) session.Scope {
	n := 32
	if protocol == session.DKLS23 {
		n = 33
	}
	return session.Scope{Protocol: protocol, PublicKey: strings.Repeat("x", n), PartyID: 1}
}

func request(version session.Version, kind session.Kind, id string, round int) session.Request {
	return session.Request{Version: version, ID: session.ID{Kind: kind, Epoch: version.Epoch, Value: id}, Round: round, Participants: []int{1, 2, 3}}
}

func update(input session.Input) (session.Update, error) {
	terminal := 3
	if input.Scope.Protocol == session.FROST && input.ID.Kind == session.Signing {
		terminal = 2
	}
	checkpoint := []byte(fmt.Sprintf("private round %d", input.Round))
	if input.Round == terminal {
		checkpoint = nil
	}
	nonce := ""
	if input.ID.Kind == session.Signing && input.Round == 1 {
		n := 64
		if input.Scope.Protocol == session.DKLS23 {
			n = 33
		}
		nonce = strings.Repeat(input.ID.Value[:1], n)
	}
	return session.Update{KeyCheckpoint: []byte("updated key"), Checkpoint: checkpoint, Output: []byte(fmt.Sprintf("output %s %d", input.ID.Value, input.Round)), NonceID: nonce}, nil
}

func initialize(t *testing.T, model *storetest.Model, owner session.Scope) session.Version {
	t.Helper()
	v, err := session.Initialize(context.Background(), model.Open(), owner, 0, []byte("initial key"))
	require.NoError(t, err)
	require.Equal(t, session.Version{Epoch: 0, Revision: 1}, v)
	return v
}

func TestRoundsCommitOnceAcrossConnections(t *testing.T) {
	t.Parallel()
	for _, protocol := range []session.Protocol{session.DKLS23, session.FROST} {
		t.Run(string(protocol), func(t *testing.T) {
			t.Parallel()
			model := &storetest.Model{}
			owner := scope(protocol)
			version := initialize(t, model, owner)
			last := 3
			if protocol == session.FROST {
				last = 2
			}
			for round := 1; round <= last; round++ {
				req := request(version, session.Signing, "sign", round)
				var computations atomic.Int32
				type result struct {
					receipt *session.Receipt
					err     error
				}
				results := make(chan result, 8)
				start := make(chan struct{})
				for range 8 {
					go func() {
						<-start
						r, err := session.Advance(context.Background(), model.Open(), owner, req, func(in session.Input) (session.Update, error) { computations.Add(1); return update(in) })
						results <- result{r, err}
					}()
				}
				close(start)
				successes := 0
				for range 8 {
					out := <-results
					if out.err == nil {
						successes++
						version = out.receipt.Version
					} else {
						require.Nil(t, out.receipt)
						require.ErrorIs(t, out.err, session.ErrStale)
					}
				}
				require.Equal(t, 1, successes)
				require.EqualValues(t, 1, computations.Load())
				retry := req
				retry.Version = version
				r, err := session.Advance(context.Background(), model.Open(), owner, retry, update)
				require.ErrorIs(t, err, session.ErrProgress)
				require.Nil(t, r)
			}
			for round := 1; round <= last; round++ {
				output, err := session.Output(context.Background(), model.Open(), owner, request(version, session.Signing, "sign", round).ID, round)
				require.NoError(t, err)
				require.Equal(t, []byte(fmt.Sprintf("output sign %d", round)), output)
			}
			key, err := session.InspectKey(context.Background(), model.Open(), owner)
			require.NoError(t, err)
			require.Zero(t, key.ActiveSessions)
			record, err := session.InspectSession(context.Background(), model.Open(), owner, request(version, session.Signing, "sign", 1).ID)
			require.NoError(t, err)
			require.True(t, record.Completed)
			require.Empty(t, record.Checkpoint)
		})
	}
}

func TestCommitFailuresReleaseNoOutputAndRecoverFromStore(t *testing.T) {
	t.Parallel()
	for _, failure := range []storetest.Failure{storetest.BeforeCommit, storetest.AfterCommit} {
		t.Run(fmt.Sprint(failure), func(t *testing.T) {
			t.Parallel()
			model := &storetest.Model{}
			owner := scope(session.FROST)
			version := initialize(t, model, owner)
			req := request(version, session.Signing, "sign", 1)
			model.FailNext(failure)
			r, err := session.Advance(context.Background(), model.Open(), owner, req, update)
			require.ErrorIs(t, err, storetest.ErrInjected)
			require.Nil(t, r)
			key, err := session.InspectKey(context.Background(), model.Open(), owner)
			require.NoError(t, err)
			if failure == storetest.BeforeCommit {
				require.Equal(t, version, key.Version)
				_, err = session.Output(context.Background(), model.Open(), owner, req.ID, 1)
				require.ErrorIs(t, err, session.ErrMissing)
				r, err = session.Advance(context.Background(), model.Open(), owner, req, update)
				require.NoError(t, err)
				require.Equal(t, []byte("output sign 1"), r.Output)
			} else {
				require.Equal(t, version.Revision+1, key.Revision)
				output, err := session.Output(context.Background(), model.Open(), owner, req.ID, 1)
				require.NoError(t, err)
				require.Equal(t, []byte("output sign 1"), output)
				req.Version = key.Version
				_, err = session.Advance(context.Background(), model.Open(), owner, req, update)
				require.ErrorIs(t, err, session.ErrProgress)
			}
		})
	}
}

func TestRolledBackRoundCanBeRecomputedBeforeCommit(t *testing.T) {
	t.Parallel()
	for _, protocol := range []session.Protocol{session.DKLS23, session.FROST} {
		t.Run(string(protocol), func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			model := &storetest.Model{}
			owner := scope(protocol)
			version := initialize(t, model, owner)
			before, err := session.InspectKey(ctx, model.Open(), owner)
			require.NoError(t, err)
			req := request(version, session.Signing, "sign", 1)
			var computations atomic.Int32
			compute := func(in session.Input) (session.Update, error) {
				attempt := computations.Add(1)
				u, err := update(in)
				u.Output = []byte(fmt.Sprintf("attempt %d", attempt))
				return u, err
			}

			model.FailNext(storetest.BeforeCommit)
			r, err := session.Advance(ctx, model.Open(), owner, req, compute)
			require.ErrorIs(t, err, storetest.ErrInjected)
			require.Nil(t, r)
			require.EqualValues(t, 1, computations.Load())
			key, err := session.InspectKey(ctx, model.Open(), owner)
			require.NoError(t, err)
			require.Equal(t, before, key, "rollback preserves authoritative progress")
			_, err = session.InspectSession(ctx, model.Open(), owner, req.ID)
			require.ErrorIs(t, err, session.ErrMissing)
			_, err = session.Output(ctx, model.Open(), owner, req.ID, 1)
			require.ErrorIs(t, err, session.ErrMissing)

			// A new explicit call can recompute the same round after confirmed
			// rollback; only the second attempt's result becomes authoritative.
			r, err = session.Advance(ctx, model.Open(), owner, req, compute)
			require.NoError(t, err)
			require.EqualValues(t, 2, computations.Load())
			require.Equal(t, []byte("attempt 2"), r.Output)
			require.Equal(t, version.Revision+1, r.Revision)
			output, err := session.Output(ctx, model.Open(), owner, req.ID, 1)
			require.NoError(t, err)
			require.Equal(t, r.Output, output)
			record, err := session.InspectSession(ctx, model.Open(), owner, req.ID)
			require.NoError(t, err)
			require.Equal(t, 1, record.Round)
			require.Equal(t, map[int][]byte{1: []byte("attempt 2")}, record.Outputs)

			req.Version = r.Version
			r, err = session.Advance(ctx, model.Open(), owner, req, compute)
			require.ErrorIs(t, err, session.ErrProgress)
			require.Nil(t, r)
			require.EqualValues(t, 2, computations.Load(), "committed rounds are not recomputed")
		})
	}
}

func TestStaleBackupAndNonceReuseAreRejected(t *testing.T) {
	t.Parallel()
	model := &storetest.Model{}
	owner := scope(session.FROST)
	backup := initialize(t, model, owner)
	r, err := session.Advance(context.Background(), model.Open(), owner, request(backup, session.Signing, "first", 1), update)
	require.NoError(t, err)
	_, err = session.Advance(context.Background(), model.Open(), owner, request(backup, session.Signing, "fresh id", 1), update)
	require.ErrorIs(t, err, session.ErrStale)
	_, err = session.Advance(context.Background(), model.Open(), owner, request(r.Version, session.Signing, "fresh id", 1), update)
	require.ErrorIs(t, err, session.ErrNonceUsed, "both session names derive the same test nonce marker")
	_, err = session.Initialize(context.Background(), model.Open(), owner, 0, []byte("old backup"))
	require.ErrorIs(t, err, session.ErrInitialized)
}

func TestComputationFailureAndPanicRollBack(t *testing.T) {
	t.Parallel()
	model := &storetest.Model{}
	owner := scope(session.DKLS23)
	version := initialize(t, model, owner)
	req := request(version, session.Signing, "sign", 1)
	failure := errors.New("computation failed")
	r, err := session.Advance(context.Background(), model.Open(), owner, req, func(session.Input) (session.Update, error) { return session.Update{}, failure })
	require.ErrorIs(t, err, failure)
	require.Nil(t, r)
	require.PanicsWithValue(t, "panic before commit", func() {
		_, _ = session.Advance(context.Background(), model.Open(), owner, req, func(session.Input) (session.Update, error) { panic("panic before commit") })
	})
	key, err := session.InspectKey(context.Background(), model.Open(), owner)
	require.NoError(t, err)
	require.Equal(t, version, key.Version)
	_, err = session.Advance(context.Background(), model.Open(), owner, req, update)
	require.NoError(t, err)
}

func TestRefreshQuiescesSigningAndRequiresExplicitActivation(t *testing.T) {
	t.Parallel()
	model := &storetest.Model{}
	owner := scope(session.DKLS23)
	v := initialize(t, model, owner)
	r, err := session.Advance(context.Background(), model.Open(), owner, request(v, session.Signing, "sign", 1), update)
	require.NoError(t, err)
	v = r.Version
	_, err = session.Advance(context.Background(), model.Open(), owner, request(v, session.Refresh, "refresh", 1), update)
	require.ErrorIs(t, err, session.ErrBusy)
	v, err = session.Abort(context.Background(), model.Open(), owner, v, request(v, session.Signing, "sign", 1).ID)
	require.NoError(t, err)
	old := v
	for round := 1; round <= 3; round++ {
		r, err = session.Advance(context.Background(), model.Open(), owner, request(v, session.Refresh, "refresh", round), func(in session.Input) (session.Update, error) {
			u, err := update(in)
			if in.Round == 3 {
				u.KeyCheckpoint = []byte("new epoch key")
			}
			return u, err
		})
		require.NoError(t, err)
		v = r.Version
		key, err := session.InspectKey(context.Background(), model.Open(), owner)
		require.NoError(t, err)
		require.Zero(t, key.Epoch)
		require.NotNil(t, key.Refresh)
		require.Equal(t, round == 3, key.Refresh.Prepared)
		_, err = session.Advance(context.Background(), model.Open(), owner, request(v, session.Signing, "fresh", 1), update)
		require.ErrorIs(t, err, session.ErrBusy)
		if round != 3 {
			_, err = session.Activate(context.Background(), model.Open(), owner, v, "refresh")
			require.ErrorIs(t, err, session.ErrProgress)
		}
	}
	// Competing activation calls use independent frontend connections.
	type activation struct {
		version session.Version
		err     error
	}
	results := make(chan activation, 8)
	for range 8 {
		go func() {
			next, err := session.Activate(context.Background(), model.Open(), owner, v, "refresh")
			results <- activation{next, err}
		}()
	}
	successes := 0
	var activated session.Version
	for range 8 {
		out := <-results
		if out.err == nil {
			successes++
			activated = out.version
		} else {
			require.ErrorIs(t, out.err, session.ErrStale)
		}
	}
	require.Equal(t, 1, successes)
	require.Equal(t, 1, activated.Epoch)
	_, err = session.Activate(context.Background(), model.Open(), owner, activated, "refresh")
	require.ErrorIs(t, err, session.ErrProgress)
	_, err = session.Advance(context.Background(), model.Open(), owner, request(old, session.Signing, "fresh", 1), update)
	require.ErrorIs(t, err, session.ErrStale)
	// The old signing ID is fresh in the re-keyed epoch, but its nonce marker is not.
	_, err = session.Advance(context.Background(), model.Open(), owner, request(activated, session.Signing, "sign", 1), update)
	require.ErrorIs(t, err, session.ErrNonceUsed)
	key, err := session.InspectKey(context.Background(), model.Open(), owner)
	require.NoError(t, err)
	require.Equal(t, []byte("new epoch key"), key.Checkpoint)
	require.Nil(t, key.Refresh)
}

func TestAbortAndBlacklistSurviveReopening(t *testing.T) {
	t.Parallel()
	model := &storetest.Model{}
	owner := scope(session.FROST)
	v := initialize(t, model, owner)
	req := request(v, session.Signing, "sign", 1)
	r, err := session.Advance(context.Background(), model.Open(), owner, req, update)
	require.NoError(t, err)
	v, err = session.Abort(context.Background(), model.Open(), owner, r.Version, req.ID)
	require.NoError(t, err)
	_, err = session.Abort(context.Background(), model.Open(), owner, v, req.ID)
	require.ErrorIs(t, err, session.ErrAborted)
	req.Version = v
	_, err = session.Advance(context.Background(), model.Open(), owner, req, update)
	require.ErrorIs(t, err, session.ErrAborted)
	v, err = session.Blacklist(context.Background(), model.Open(), owner, v, []int{3, 2, 3})
	require.NoError(t, err)
	_, err = session.Advance(context.Background(), model.Open(), owner, request(v, session.Signing, "fresh", 1), update)
	require.ErrorIs(t, err, session.ErrBlacklisted)
	key, err := session.InspectKey(context.Background(), model.Open(), owner)
	require.NoError(t, err)
	require.Equal(t, []int{2, 3}, key.Blacklist)
	record, err := session.InspectSession(context.Background(), model.Open(), owner, req.ID)
	require.NoError(t, err)
	require.Empty(t, record.Checkpoint)
	require.True(t, record.Aborted)
}

func TestProtocolAbortCommitsBlacklistButWithholdsOutput(t *testing.T) {
	t.Parallel()
	model := &storetest.Model{}
	owner := scope(session.DKLS23)
	v := initialize(t, model, owner)
	failure := errors.New("verified protocol failure")
	req := request(v, session.Signing, "aborted", 1)
	r, err := session.Advance(context.Background(), model.Open(), owner, req, func(session.Input) (session.Update, error) {
		return session.Update{KeyCheckpoint: []byte("key with updated blacklist"), Blacklist: []int{2}, Abort: failure}, nil
	})
	require.ErrorIs(t, err, failure)
	require.Nil(t, r)
	key, err := session.InspectKey(context.Background(), model.Open(), owner)
	require.NoError(t, err)
	require.Equal(t, []int{2}, key.Blacklist)
	record, err := session.InspectSession(context.Background(), model.Open(), owner, req.ID)
	require.NoError(t, err)
	require.True(t, record.Aborted)
	require.Empty(t, record.Outputs)
	require.Empty(t, record.Checkpoint)
}
