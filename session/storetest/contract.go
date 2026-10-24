package storetest

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/chrisalmeida/go-mpc/session"
)

// Factory opens an isolated test store and returns a function that reopens its
// same committed data through a new connection. Register backend cleanup with t.
// Reopening must not initialize the records again. A real adapter should close
// and reopen its actual storage; Model's factory models connection loss only.
type Factory func(t *testing.T) (session.Store, func() session.Store)

// Run tests transaction atomicity, rollback of tentative writes while preserving
// committed records, namespace separation, copying, concurrent serialization and
// visibility through reopened connections. Run it under -race for each production
// Store adapter; both resumable and in-memory modes must survive reopening.
// Passing is necessary, but does not establish every part of the
// Store contract or simulate power loss or restoration of an old database snapshot.
func Run(t *testing.T, factory Factory) {
	t.Helper()
	owner := session.Scope{Protocol: session.DKLS23, PublicKey: strings.Repeat("x", 33), PartyID: 1}
	id := session.ID{Kind: session.Signing, Epoch: 0, Value: "contract"}
	key := func() session.KeyRecord {
		return session.KeyRecord{Version: session.Version{Epoch: 0, Revision: 1}, Checkpoint: []byte("key"), Blacklist: []int{3}, Refresh: &session.PendingRefresh{SessionID: "refresh", Prepared: true, Checkpoint: []byte("candidate")}}
	}
	record := func() session.Record {
		return session.Record{Round: 1, Participants: []int{1, 2}, Checkpoint: []byte("private"), Outputs: map[int][]byte{1: []byte("public")}}
	}
	check := func(t *testing.T, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Run("commit survives reopening", func(t *testing.T) {
		t.Parallel()
		store, reopen := factory(t)
		check(t, store.Transact(context.Background(), owner, func(tx session.Transaction) error {
			if err := tx.PutKey(key()); err != nil {
				return err
			}
			if err := tx.PutSession(id, record()); err != nil {
				return err
			}
			return tx.UseNonce("nonce")
		}))
		check(t, reopen().Transact(context.Background(), owner, func(tx session.Transaction) error {
			got, found, err := tx.Key()
			if err != nil {
				return err
			}
			if !found || string(got.Checkpoint) != "key" || string(got.Refresh.Checkpoint) != "candidate" {
				t.Error("committed key not recovered")
			}
			r, found, err := tx.Session(id)
			if err != nil {
				return err
			}
			if !found || string(r.Checkpoint) != "private" || string(r.Outputs[1]) != "public" {
				t.Error("committed session not recovered")
			}
			used, err := tx.NonceUsed("nonce")
			if err == nil && !used {
				t.Error("nonce reservation not recovered")
			}
			return err
		}))
	})
	t.Run("operation modes survive reopening", func(t *testing.T) {
		t.Parallel()
		store, reopen := factory(t)
		for _, mode := range []session.Mode{session.InMemory, session.Resumable} {
			expected := record()
			expected.Mode = mode
			if mode == session.InMemory {
				expected.Checkpoint = nil
			}
			check(t, store.Transact(context.Background(), owner, func(tx session.Transaction) error {
				return tx.PutSession(id, expected)
			}))
			check(t, reopen().Transact(context.Background(), owner, func(tx session.Transaction) error {
				got, found, err := tx.Session(id)
				if err != nil {
					return err
				}
				if !found || got.Mode != mode {
					t.Errorf("operation mode not recovered: want %q, got %q (found=%v)", mode, got.Mode, found)
				}
				return nil
			}))
		}
	})
	for _, panics := range []bool{false, true} {
		for _, populated := range []bool{false, true} {
			t.Run(fmt.Sprintf("rollback populated=%v panic=%v", populated, panics), func(t *testing.T) {
				t.Parallel()
				store, reopen := factory(t)
				if populated {
					check(t, store.Transact(context.Background(), owner, func(tx session.Transaction) error {
						if err := tx.PutKey(key()); err != nil {
							return err
						}
						if err := tx.PutSession(id, record()); err != nil {
							return err
						}
						return tx.UseNonce("committed nonce")
					}))
				}
				newID := session.ID{Kind: id.Kind, Epoch: id.Epoch, Value: "uncommitted"}
				failure := errors.New("rollback sentinel")
				func() {
					defer func() {
						value := recover()
						if panics && value != failure {
							t.Errorf("panic not propagated: %v", value)
						}
						if !panics && value != nil {
							t.Errorf("unexpected panic: %v", value)
						}
					}()
					err := reopen().Transact(context.Background(), owner, func(tx session.Transaction) error {
						changedKey := session.KeyRecord{Version: session.Version{Epoch: 1, Revision: 2}, Checkpoint: []byte("replacement key"), Blacklist: []int{2}, ActiveSessions: 1}
						if err := tx.PutKey(changedKey); err != nil {
							return err
						}
						changedSession := session.Record{Round: 2, Participants: []int{1, 3}, Checkpoint: []byte("replacement private"), Outputs: map[int][]byte{1: []byte("replacement output"), 2: []byte("new output")}}
						if err := tx.PutSession(id, changedSession); err != nil {
							return err
						}
						if err := tx.PutSession(newID, record()); err != nil {
							return err
						}
						if err := tx.UseNonce("nonce"); err != nil {
							return err
						}
						if panics {
							panic(failure)
						}
						return failure
					})
					if panics {
						t.Error("panic swallowed")
					} else if !errors.Is(err, failure) {
						t.Errorf("callback error not preserved: %v", err)
					}
				}()
				check(t, reopen().Transact(context.Background(), owner, func(tx session.Transaction) error {
					gotKey, found, err := tx.Key()
					if err != nil {
						return err
					}
					if populated && (!found || !reflect.DeepEqual(gotKey, key())) {
						t.Error("committed key changed after rollback")
					} else if !populated && found {
						t.Error("key write leaked through rollback")
					}
					gotSession, found, err := tx.Session(id)
					if err != nil {
						return err
					}
					if populated && (!found || !reflect.DeepEqual(gotSession, record())) {
						t.Error("committed session changed after rollback")
					} else if !populated && found {
						t.Error("session write leaked through rollback")
					}
					_, found, err = tx.Session(newID)
					if err != nil {
						return err
					}
					if found {
						t.Error("new session write leaked through rollback")
					}
					used, err := tx.NonceUsed("committed nonce")
					if err != nil {
						return err
					}
					if populated && !used {
						t.Error("committed nonce reservation lost after rollback")
					}
					used, err = tx.NonceUsed("nonce")
					if err == nil && used {
						t.Error("nonce write leaked through rollback")
					}
					return err
				}))
			})
		}
	}
	t.Run("records and arguments do not alias", func(t *testing.T) {
		t.Parallel()
		store, reopen := factory(t)
		check(t, store.Transact(context.Background(), owner, func(tx session.Transaction) error {
			k, r := key(), record()
			if err := tx.PutKey(k); err != nil {
				return err
			}
			if err := tx.PutSession(id, r); err != nil {
				return err
			}
			k.Checkpoint[0] ^= 1
			k.Blacklist[0] = 99
			k.Refresh.Checkpoint[0] ^= 1
			r.Participants[0] = 99
			r.Checkpoint[0] ^= 1
			r.Outputs[1][0] ^= 1
			return nil
		}))
		for range 2 {
			check(t, reopen().Transact(context.Background(), owner, func(tx session.Transaction) error {
				k, _, err := tx.Key()
				if err != nil {
					return err
				}
				r, _, err := tx.Session(id)
				if err != nil {
					return err
				}
				if string(k.Checkpoint) != "key" || k.Blacklist[0] != 3 || string(k.Refresh.Checkpoint) != "candidate" || r.Participants[0] != 1 || string(r.Checkpoint) != "private" || string(r.Outputs[1]) != "public" {
					t.Error("transaction records alias caller buffers")
				}
				k.Checkpoint[0] ^= 1
				k.Blacklist[0] = 99
				k.Refresh.Checkpoint[0] ^= 1
				r.Participants[0] = 99
				r.Checkpoint[0] ^= 1
				r.Outputs[1][0] ^= 1
				return nil
			}))
		}
	})
	t.Run("concurrent connections serialize", func(t *testing.T) {
		t.Parallel()
		store, reopen := factory(t)
		check(t, store.Transact(context.Background(), owner, func(tx session.Transaction) error { return tx.PutKey(key()) }))
		const workers = 8
		results := make(chan error, workers)
		for range workers {
			go func(store session.Store) {
				results <- store.Transact(context.Background(), owner, func(tx session.Transaction) error {
					k, _, err := tx.Key()
					if err != nil {
						return err
					}
					k.Revision++
					return tx.PutKey(k)
				})
			}(reopen())
		}
		for range workers {
			check(t, <-results)
		}
		check(t, reopen().Transact(context.Background(), owner, func(tx session.Transaction) error {
			k, _, err := tx.Key()
			if err == nil && k.Revision != workers+1 {
				t.Errorf("lost update: revision %d", k.Revision)
			}
			return err
		}))
	})
	t.Run("scope and operation namespaces", func(t *testing.T) {
		t.Parallel()
		store, reopen := factory(t)
		check(t, store.Transact(context.Background(), owner, func(tx session.Transaction) error {
			if err := tx.PutKey(key()); err != nil {
				return err
			}
			if err := tx.PutSession(id, record()); err != nil {
				return err
			}
			return tx.UseNonce("nonce")
		}))
		for _, other := range []session.Scope{{Protocol: owner.Protocol, PublicKey: owner.PublicKey, PartyID: 2}, {Protocol: owner.Protocol, PublicKey: strings.Repeat("y", 33), PartyID: 1}, {Protocol: session.FROST, PublicKey: strings.Repeat("x", 32), PartyID: 1}} {
			check(t, reopen().Transact(context.Background(), other, func(tx session.Transaction) error {
				_, found, err := tx.Key()
				if err != nil {
					return err
				}
				if found {
					t.Error("key namespaces collide")
				}
				_, found, err = tx.Session(id)
				if err != nil {
					return err
				}
				if found {
					t.Error("session namespaces collide")
				}
				used, err := tx.NonceUsed("nonce")
				if err == nil && used {
					t.Error("nonce namespaces collide")
				}
				return err
			}))
		}
		check(t, reopen().Transact(context.Background(), owner, func(tx session.Transaction) error {
			for _, other := range []session.ID{{Kind: id.Kind, Epoch: id.Epoch, Value: "other"}, {Kind: id.Kind, Epoch: 1, Value: id.Value}, {Kind: session.Refresh, Epoch: id.Epoch, Value: id.Value}} {
				_, found, err := tx.Session(other)
				if err != nil {
					return err
				}
				if found {
					t.Error("operation identifiers collide")
				}
			}
			return nil
		}))
	})
}
