package session_test

import (
	"context"
	"errors"
	"math"
	"slices"
	"strings"
	"testing"

	"github.com/chrisalmeida/go-mpc/session"
	"github.com/chrisalmeida/go-mpc/session/storetest"
	"github.com/stretchr/testify/require"
)

var errFault = errors.New("injected store fault")

// faultStore fails exactly one Transaction method so that every propagation
// path in the guard is exercised against an otherwise conforming store.
type faultStore struct {
	inner session.Store
	fail  string
}

func (s *faultStore) Transact(ctx context.Context, scope session.Scope, fn func(session.Transaction) error) error {
	return s.inner.Transact(ctx, scope, func(tx session.Transaction) error {
		return fn(&faultTx{Transaction: tx, fail: s.fail})
	})
}

type faultTx struct {
	session.Transaction
	fail string
}

func (tx *faultTx) Key() (session.KeyRecord, bool, error) {
	if tx.fail == "Key" {
		return session.KeyRecord{}, false, errFault
	}
	return tx.Transaction.Key()
}

func (tx *faultTx) PutKey(record session.KeyRecord) error {
	if tx.fail == "PutKey" {
		return errFault
	}
	return tx.Transaction.PutKey(record)
}

func (tx *faultTx) Session(id session.ID) (session.Record, bool, error) {
	if tx.fail == "Session" {
		return session.Record{}, false, errFault
	}
	return tx.Transaction.Session(id)
}

func (tx *faultTx) PutSession(id session.ID, record session.Record) error {
	if tx.fail == "PutSession" {
		return errFault
	}
	return tx.Transaction.PutSession(id, record)
}

func (tx *faultTx) NonceUsed(id string) (bool, error) {
	if tx.fail == "NonceUsed" {
		return false, errFault
	}
	return tx.Transaction.NonceUsed(id)
}

func (tx *faultTx) UseNonce(id string) error {
	if tx.fail == "UseNonce" {
		return errFault
	}
	return tx.Transaction.UseNonce(id)
}

// misbehavingStore violates the Store callback contract in one chosen way.
type misbehavingStore struct {
	inner  session.Store
	calls  int
	nilTx  bool
	cancel context.CancelFunc
}

func (s *misbehavingStore) Transact(_ context.Context, scope session.Scope, fn func(session.Transaction) error) error {
	return s.inner.Transact(context.Background(), scope, func(tx session.Transaction) error {
		if s.cancel != nil {
			s.cancel()
		}
		if s.nilTx {
			return fn(nil)
		}
		var err error
		for range s.calls {
			err = fn(tx)
		}
		return err
	})
}

type fixture func(t *testing.T) (*storetest.Model, session.Scope, session.Version)

func fresh(*testing.T) (*storetest.Model, session.Scope, session.Version) {
	return &storetest.Model{}, scope(session.DKLS23), session.Version{}
}

// signingInProgress initializes a DKLS23 scope and completes signing round 1
// for the operation "sign".
func signingInProgress(t *testing.T) (*storetest.Model, session.Scope, session.Version) {
	t.Helper()
	model := &storetest.Model{}
	owner := scope(session.DKLS23)
	v := initialize(t, model, owner)
	r, err := session.Advance(context.Background(), model.Open(), owner, request(v, session.Signing, "sign", 1), update)
	require.NoError(t, err)
	return model, owner, r.Version
}

// refreshInProgress initializes a DKLS23 scope and completes refresh round 1.
func refreshInProgress(t *testing.T) (*storetest.Model, session.Scope, session.Version) {
	t.Helper()
	model := &storetest.Model{}
	owner := scope(session.DKLS23)
	v := initialize(t, model, owner)
	r, err := session.Advance(context.Background(), model.Open(), owner, request(v, session.Refresh, "refresh", 1), update)
	require.NoError(t, err)
	return model, owner, r.Version
}

// refreshPrepared finalizes a refresh locally without activating it.
func refreshPrepared(t *testing.T) (*storetest.Model, session.Scope, session.Version) {
	t.Helper()
	model := &storetest.Model{}
	owner := scope(session.DKLS23)
	v := initialize(t, model, owner)
	for round := 1; round <= 3; round++ {
		r, err := session.Advance(context.Background(), model.Open(), owner, request(v, session.Refresh, "refresh", round), update)
		require.NoError(t, err)
		v = r.Version
	}
	return model, owner, v
}

// write edits records directly, bypassing the guard, to model corruption.
func write(t *testing.T, model *storetest.Model, owner session.Scope, fn func(tx session.Transaction) error) {
	t.Helper()
	require.NoError(t, model.Open().Transact(context.Background(), owner, fn))
}

func keyRecord(t *testing.T, model *storetest.Model, owner session.Scope) (session.KeyRecord, error) {
	t.Helper()
	return session.InspectKey(context.Background(), model.Open(), owner)
}

func TestStoreErrorsPropagateAndCommitNothing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	signID := session.ID{Kind: session.Signing, Epoch: 0, Value: "sign"}
	operations := []struct {
		name    string
		prepare fixture
		run     func(store session.Store, owner session.Scope, v session.Version) error
		touches []string
	}{
		{"Initialize", fresh, func(store session.Store, owner session.Scope, _ session.Version) error {
			_, err := session.Initialize(ctx, store, owner, 0, []byte("key"))
			return err
		}, []string{"Key", "PutKey"}},
		{"InspectKey", signingInProgress, func(store session.Store, owner session.Scope, _ session.Version) error {
			_, err := session.InspectKey(ctx, store, owner)
			return err
		}, []string{"Key"}},
		{"InspectSession", signingInProgress, func(store session.Store, owner session.Scope, _ session.Version) error {
			_, err := session.InspectSession(ctx, store, owner, signID)
			return err
		}, []string{"Key", "Session"}},
		{"Advance round 1", signingInProgress, func(store session.Store, owner session.Scope, v session.Version) error {
			_, err := session.Advance(ctx, store, owner, request(v, session.Signing, "other", 1), update)
			return err
		}, []string{"Key", "Session", "NonceUsed", "UseNonce", "PutKey", "PutSession"}},
		{"Advance round 2", signingInProgress, func(store session.Store, owner session.Scope, v session.Version) error {
			_, err := session.Advance(ctx, store, owner, request(v, session.Signing, "sign", 2), update)
			return err
		}, []string{"Key", "Session", "PutKey", "PutSession"}},
		{"Output", signingInProgress, func(store session.Store, owner session.Scope, _ session.Version) error {
			_, err := session.Output(ctx, store, owner, signID, 1)
			return err
		}, []string{"Key", "Session"}},
		{"Abort", signingInProgress, func(store session.Store, owner session.Scope, v session.Version) error {
			_, err := session.Abort(ctx, store, owner, v, signID)
			return err
		}, []string{"Key", "Session", "PutSession", "PutKey"}},
		{"Blacklist", signingInProgress, func(store session.Store, owner session.Scope, v session.Version) error {
			_, err := session.Blacklist(ctx, store, owner, v, []int{3})
			return err
		}, []string{"Key", "PutKey"}},
		{"Activate", refreshPrepared, func(store session.Store, owner session.Scope, v session.Version) error {
			_, err := session.Activate(ctx, store, owner, v, "refresh")
			return err
		}, []string{"Key", "Session", "PutKey"}},
	}
	for _, op := range operations {
		for _, method := range []string{"Key", "PutKey", "Session", "PutSession", "NonceUsed", "UseNonce"} {
			t.Run(op.name+"/"+method, func(t *testing.T) {
				t.Parallel()
				model, owner, v := op.prepare(t)
				before, beforeErr := keyRecord(t, model, owner)
				err := op.run(&faultStore{inner: model.Open(), fail: method}, owner, v)
				if !slices.Contains(op.touches, method) {
					require.NoError(t, err)
					return
				}
				require.ErrorIs(t, err, errFault)
				after, afterErr := keyRecord(t, model, owner)
				require.Equal(t, beforeErr == nil, afterErr == nil)
				require.Equal(t, before, after, "a failed transaction must commit nothing")
			})
		}
	}
}

func TestInvalidRequestsAreRejectedBeforeCompute(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	model, owner, v := signingInProgress(t)
	store := model.Open()
	untouched := func(session.Input) (session.Update, error) {
		return session.Update{}, errors.New("compute must not run")
	}
	valid := request(v, session.Signing, "other", 1)
	mutate := func(f func(*session.Request)) session.Request {
		r := valid
		r.Participants = slices.Clone(r.Participants)
		f(&r)
		return r
	}
	for name, req := range map[string]session.Request{
		"unknown kind":          mutate(func(r *session.Request) { r.ID.Kind = "other" }),
		"empty id":              mutate(func(r *session.Request) { r.ID.Value = "" }),
		"epoch mismatch":        mutate(func(r *session.Request) { r.ID.Epoch = 1 }),
		"zero revision":         mutate(func(r *session.Request) { r.Revision = 0 }),
		"round zero":            mutate(func(r *session.Request) { r.Round = 0 }),
		"round past final":      mutate(func(r *session.Request) { r.Round = 4 }),
		"no participants":       mutate(func(r *session.Request) { r.Participants = nil }),
		"duplicate participant": mutate(func(r *session.Request) { r.Participants = []int{1, 2, 2} }),
		"participant zero":      mutate(func(r *session.Request) { r.Participants = []int{0, 1} }),
		"own id missing":        mutate(func(r *session.Request) { r.Participants = []int{2, 3} }),
	} {
		_, err := session.Advance(ctx, store, owner, req, untouched)
		require.ErrorIs(t, err, session.ErrInvalid, name)
	}
	_, err := session.Advance(ctx, store, owner, valid, nil)
	require.ErrorIs(t, err, session.ErrInvalid)

	// Scope, store and context validation happen before any transaction.
	bad := owner
	bad.PublicKey = "short"
	_, err = session.InspectKey(ctx, store, bad)
	require.ErrorIs(t, err, session.ErrInvalid)
	_, err = session.InspectKey(ctx, nil, owner)
	require.ErrorIs(t, err, session.ErrInvalid)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = session.InspectKey(cancelled, store, owner)
	require.ErrorIs(t, err, context.Canceled)

	// Every other entry point validates its arguments.
	_, err = session.Initialize(ctx, store, scope(session.FROST), -1, []byte("key"))
	require.ErrorIs(t, err, session.ErrInvalid)
	_, err = session.Initialize(ctx, store, scope(session.FROST), 0, nil)
	require.ErrorIs(t, err, session.ErrInvalid)
	_, err = session.InspectSession(ctx, store, owner, session.ID{})
	require.ErrorIs(t, err, session.ErrInvalid)
	_, err = session.Output(ctx, store, owner, valid.ID, 0)
	require.ErrorIs(t, err, session.ErrInvalid)
	_, err = session.Output(ctx, store, owner, valid.ID, 4)
	require.ErrorIs(t, err, session.ErrInvalid)
	_, err = session.Abort(ctx, store, owner, v, session.ID{Kind: session.Signing, Epoch: v.Epoch + 1, Value: "sign"})
	require.ErrorIs(t, err, session.ErrInvalid)
	_, err = session.Activate(ctx, store, owner, v, "")
	require.ErrorIs(t, err, session.ErrInvalid)
	_, err = session.Blacklist(ctx, store, owner, v, []int{0})
	require.ErrorIs(t, err, session.ErrInvalid)

	key, err := keyRecord(t, model, owner)
	require.NoError(t, err)
	require.Equal(t, v, key.Version, "rejected requests must not change the authoritative version")
}

func TestInvalidUpdatesAreRejectedWithoutCommit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	model, owner, v := signingInProgress(t)
	store := model.Open()
	r, err := session.Advance(ctx, store, owner, request(v, session.Signing, "sign", 2), update)
	require.NoError(t, err)
	v = r.Version
	start := request(v, session.Signing, "other", 1)
	final := request(v, session.Signing, "sign", 3)
	tweak := func(f func(*session.Update)) session.Compute {
		return func(in session.Input) (session.Update, error) {
			u, err := update(in)
			f(&u)
			return u, err
		}
	}
	for _, tc := range []struct {
		name    string
		req     session.Request
		compute session.Compute
	}{
		{"empty key checkpoint", start, tweak(func(u *session.Update) { u.KeyCheckpoint = nil })},
		{"abort carrying output", start, tweak(func(u *session.Update) { u.Abort = errors.New("abort") })},
		{"missing private checkpoint", start, tweak(func(u *session.Update) { u.Checkpoint = nil })},
		{"nonce marker width", start, tweak(func(u *session.Update) { u.NonceID = "short" })},
		{"terminal round keeps checkpoint", final, tweak(func(u *session.Update) { u.Checkpoint = []byte("leftover") })},
		{"terminal round without output", final, tweak(func(u *session.Update) { u.Output = nil })},
		{"nonce marker after round 1", final, tweak(func(u *session.Update) { u.NonceID = strings.Repeat("n", 33) })},
	} {
		_, err := session.Advance(ctx, store, owner, tc.req, tc.compute)
		require.ErrorIs(t, err, session.ErrInvalid, tc.name)
	}
	// A context cancelled during the computation rolls the round back.
	cancellable, cancel := context.WithCancel(ctx)
	_, err = session.Advance(cancellable, store, owner, start, func(in session.Input) (session.Update, error) {
		cancel()
		return update(in)
	})
	require.ErrorIs(t, err, context.Canceled)

	key, err := keyRecord(t, model, owner)
	require.NoError(t, err)
	require.Equal(t, v, key.Version)
	_, err = session.Advance(ctx, store, owner, final, update)
	require.NoError(t, err, "the session stays usable after rejected updates")
}

func TestCorruptRecordsAreReportedNotRepaired(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	signID := session.ID{Kind: session.Signing, Epoch: 0, Value: "sign"}
	for name, corrupt := range map[string]func(*session.KeyRecord){
		"zero revision":           func(k *session.KeyRecord) { k.Revision = 0 },
		"negative epoch":          func(k *session.KeyRecord) { k.Epoch = -1 },
		"empty checkpoint":        func(k *session.KeyRecord) { k.Checkpoint = nil },
		"unsorted blacklist":      func(k *session.KeyRecord) { k.Blacklist = []int{3, 2} },
		"invalid blacklist id":    func(k *session.KeyRecord) { k.Blacklist = []int{0} },
		"unnamed pending refresh": func(k *session.KeyRecord) { k.ActiveSessions = 0; k.Refresh = &session.PendingRefresh{} },
		"prepared without checkpoint": func(k *session.KeyRecord) {
			k.ActiveSessions = 0
			k.Refresh = &session.PendingRefresh{SessionID: "r", Prepared: true}
		},
		"refresh with active sessions": func(k *session.KeyRecord) { k.Refresh = &session.PendingRefresh{SessionID: "r"} },
	} {
		t.Run("key/"+name, func(t *testing.T) {
			t.Parallel()
			model, owner, _ := signingInProgress(t)
			write(t, model, owner, func(tx session.Transaction) error {
				key, _, err := tx.Key()
				if err != nil {
					return err
				}
				corrupt(&key)
				return tx.PutKey(key)
			})
			_, err := session.InspectKey(ctx, model.Open(), owner)
			require.ErrorIs(t, err, session.ErrCorrupt)
		})
	}
	for name, corrupt := range map[string]func(*session.Record){
		"round zero without abort":   func(r *session.Record) { r.Round = 0; r.Outputs = map[int][]byte{} },
		"completed and aborted":      func(r *session.Record) { r.Completed, r.Aborted = true, true },
		"completed before last":      func(r *session.Record) { r.Completed = true; r.Checkpoint = nil },
		"missing output":             func(r *session.Record) { r.Outputs = map[int][]byte{} },
		"empty output":               func(r *session.Record) { r.Outputs = map[int][]byte{1: nil} },
		"participants without owner": func(r *session.Record) { r.Participants = []int{2, 3} },
		"unsorted participants":      func(r *session.Record) { r.Participants = []int{3, 2, 1} },
		"missing private checkpoint": func(r *session.Record) { r.Checkpoint = nil },
	} {
		t.Run("session/"+name, func(t *testing.T) {
			t.Parallel()
			model, owner, _ := signingInProgress(t)
			write(t, model, owner, func(tx session.Transaction) error {
				record, _, err := tx.Session(signID)
				if err != nil {
					return err
				}
				corrupt(&record)
				return tx.PutSession(signID, record)
			})
			_, err := session.InspectSession(ctx, model.Open(), owner, signID)
			require.ErrorIs(t, err, session.ErrCorrupt)
		})
	}
	t.Run("counters", func(t *testing.T) {
		t.Parallel()
		model, owner, v := signingInProgress(t)
		store := model.Open()
		setKey := func(f func(*session.KeyRecord)) {
			write(t, model, owner, func(tx session.Transaction) error {
				key, _, err := tx.Key()
				if err != nil {
					return err
				}
				f(&key)
				return tx.PutKey(key)
			})
		}
		setKey(func(k *session.KeyRecord) { k.ActiveSessions = 0 })
		_, err := session.Advance(ctx, store, owner, request(v, session.Signing, "sign", 2), update)
		require.ErrorIs(t, err, session.ErrCorrupt)
		_, err = session.Abort(ctx, store, owner, v, signID)
		require.ErrorIs(t, err, session.ErrCorrupt)
		setKey(func(k *session.KeyRecord) { k.ActiveSessions = math.MaxUint64 })
		_, err = session.Advance(ctx, store, owner, request(v, session.Signing, "other", 1), update)
		require.ErrorIs(t, err, session.ErrCorrupt)
		// A revision at its maximum cannot be advanced by any operation.
		setKey(func(k *session.KeyRecord) { k.ActiveSessions = 1; k.Revision = math.MaxUint64 })
		last := session.Version{Epoch: v.Epoch, Revision: math.MaxUint64}
		_, err = session.Advance(ctx, store, owner, request(last, session.Signing, "sign", 2), update)
		require.ErrorIs(t, err, session.ErrCorrupt)
		_, err = session.Blacklist(ctx, store, owner, last, []int{2})
		require.ErrorIs(t, err, session.ErrCorrupt)
		_, err = session.Abort(ctx, store, owner, last, signID)
		require.ErrorIs(t, err, session.ErrCorrupt)
	})
}

func TestProgressAndAbortRulesAcrossOperations(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	model, owner, v := signingInProgress(t)
	store := model.Open()
	other := request(v, session.Signing, "other", 1)

	// A new operation starts at round 1 and an existing one keeps its participants.
	_, err := session.Advance(ctx, store, owner, request(v, session.Signing, "other", 2), update)
	require.ErrorIs(t, err, session.ErrProgress)
	changed := request(v, session.Signing, "sign", 2)
	changed.Participants = []int{1, 2}
	_, err = session.Advance(ctx, store, owner, changed, update)
	require.ErrorIs(t, err, session.ErrInvalid)

	// Missing rounds, operations and keys are reported as missing.
	_, err = session.Output(ctx, store, owner, changed.ID, 2)
	require.ErrorIs(t, err, session.ErrMissing)
	_, err = session.InspectSession(ctx, store, owner, other.ID)
	require.ErrorIs(t, err, session.ErrMissing)
	_, err = session.Abort(ctx, store, owner, v, other.ID)
	require.ErrorIs(t, err, session.ErrMissing)
	_, err = session.InspectKey(ctx, store, scope(session.FROST))
	require.ErrorIs(t, err, session.ErrMissing)
	_, err = session.InspectSession(ctx, store, scope(session.FROST), changed.ID)
	require.ErrorIs(t, err, session.ErrMissing)

	// A protocol abort in a later signing round releases the session counter.
	failure := errors.New("verified protocol failure")
	abort := func(session.Input) (session.Update, error) {
		return session.Update{KeyCheckpoint: []byte("key"), Abort: failure}, nil
	}
	_, err = session.Advance(ctx, store, owner, request(v, session.Signing, "sign", 2), abort)
	require.ErrorIs(t, err, failure)
	key, err := keyRecord(t, model, owner)
	require.NoError(t, err)
	require.Zero(t, key.ActiveSessions)
	v = key.Version

	// Completed signing operations cannot be aborted.
	for round := 1; round <= 3; round++ {
		r, err := session.Advance(ctx, store, owner, request(v, session.Signing, "complete", round), update)
		require.NoError(t, err)
		v = r.Version
	}
	_, err = session.Abort(ctx, store, owner, v, request(v, session.Signing, "complete", 1).ID)
	require.ErrorIs(t, err, session.ErrProgress)

	// Only one refresh may be pending, and aborting it reopens signing.
	r, err := session.Advance(ctx, store, owner, request(v, session.Refresh, "refresh", 1), update)
	require.NoError(t, err)
	v = r.Version
	_, err = session.Advance(ctx, store, owner, request(v, session.Refresh, "another", 1), update)
	require.ErrorIs(t, err, session.ErrBusy)
	_, err = session.Advance(ctx, store, owner, request(v, session.Refresh, "refresh", 2), abort)
	require.ErrorIs(t, err, failure)
	key, err = keyRecord(t, model, owner)
	require.NoError(t, err)
	require.Nil(t, key.Refresh)
	_, err = session.Advance(ctx, store, owner, request(key.Version, session.Signing, "after", 1), update)
	require.NoError(t, err)
}

func TestRefreshAbortAndActivationConsistency(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	refreshID := session.ID{Kind: session.Refresh, Epoch: 0, Value: "refresh"}

	// An activated refresh belongs to the previous epoch and is immutable history.
	model, owner, v := refreshPrepared(t)
	store := model.Open()
	activated, err := session.Activate(ctx, store, owner, v, "refresh")
	require.NoError(t, err)
	_, err = session.Abort(ctx, store, owner, activated, refreshID)
	require.ErrorIs(t, err, session.ErrInvalid)
	record, err := session.InspectSession(ctx, store, owner, refreshID)
	require.NoError(t, err)
	require.True(t, record.Completed)
	output, err := session.Output(ctx, store, owner, refreshID, 3)
	require.NoError(t, err)
	require.Equal(t, []byte("output refresh 3"), output)

	// A prepared refresh can be abandoned before activation.
	model, owner, v = refreshPrepared(t)
	store = model.Open()
	v, err = session.Abort(ctx, store, owner, v, refreshID)
	require.NoError(t, err)
	key, err := keyRecord(t, model, owner)
	require.NoError(t, err)
	require.Nil(t, key.Refresh)
	require.Zero(t, key.Epoch)
	_, err = session.Activate(ctx, store, owner, v, "refresh")
	require.ErrorIs(t, err, session.ErrProgress)

	// A prepared key whose refresh record was aborted underneath it is corrupt.
	model, owner, v = refreshPrepared(t)
	store = model.Open()
	write(t, model, owner, func(tx session.Transaction) error {
		r, _, err := tx.Session(refreshID)
		if err != nil {
			return err
		}
		r.Completed, r.Aborted = false, true
		return tx.PutSession(refreshID, r)
	})
	_, err = session.Activate(ctx, store, owner, v, "refresh")
	require.ErrorIs(t, err, session.ErrCorrupt)

	// A pending refresh record that disagrees with the key is corrupt.
	model, owner, v = refreshInProgress(t)
	store = model.Open()
	write(t, model, owner, func(tx session.Transaction) error {
		k, _, err := tx.Key()
		if err != nil {
			return err
		}
		k.Refresh.SessionID = "other"
		return tx.PutKey(k)
	})
	_, err = session.Abort(ctx, store, owner, v, refreshID)
	require.ErrorIs(t, err, session.ErrCorrupt)
	_, err = session.Advance(ctx, store, owner, request(v, session.Refresh, "refresh", 2), update)
	require.ErrorIs(t, err, session.ErrCorrupt)
}

func TestStoreContractViolationsAreReported(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	model, owner, v := signingInProgress(t)
	for name, store := range map[string]*misbehavingStore{
		"callback skipped":  {inner: model.Open(), calls: 0},
		"callback repeated": {inner: model.Open(), calls: 2},
		"nil transaction":   {inner: model.Open(), calls: 1, nilTx: true},
	} {
		_, err := session.InspectKey(ctx, store, owner)
		require.ErrorIs(t, err, session.ErrStoreContract, name)
	}
	cancellable, cancel := context.WithCancel(ctx)
	_, err := session.InspectKey(cancellable, &misbehavingStore{inner: model.Open(), calls: 1, cancel: cancel}, owner)
	require.ErrorIs(t, err, context.Canceled)

	// A repeated callback commits nothing even though the first call wrote records.
	_, err = session.Advance(ctx, &misbehavingStore{inner: model.Open(), calls: 2}, owner, request(v, session.Signing, "sign", 2), update)
	require.ErrorIs(t, err, session.ErrStoreContract)
	key, err := keyRecord(t, model, owner)
	require.NoError(t, err)
	require.Equal(t, v, key.Version)
}
