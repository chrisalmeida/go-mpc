// Package storetest exercises session.Store adapters. Model is a deterministic
// transaction/fault simulator for library tests, not a production storage backend.
// Run's restart checks exercise the factory's reopened backend; only a real
// backend's own crash tests can establish its physical durability guarantees.
package storetest

import (
	"context"
	"errors"
	"slices"
	"sync"

	"github.com/chrisalmeida/go-mpc/session"
)

// Failure selects the commit boundary simulated by Model.FailNext.
type Failure int

const (
	// BeforeCommit loses all tentative writes and returns ErrInjected.
	BeforeCommit Failure = iota + 1
	// AfterCommit publishes all writes but returns ErrInjected, simulating a
	// committed transaction whose acknowledgement was lost.
	AfterCommit
)

// ErrInjected is the simulated storage failure reported by Model.
var ErrInjected = errors.New("storetest: injected commit failure")

type partition struct {
	key      session.KeyRecord
	hasKey   bool
	sessions map[session.ID]session.Record
	nonces   map[string]bool
}

// Model retains simulated durable records independently of frontend connections.
// Opening a new frontend does not restore or discard those records. This is a
// logical crash model; it does not write files or demonstrate host durability.
type Model struct {
	mu       sync.Mutex
	data     map[session.Scope]partition
	failNext Failure
}

// Open returns a new connection to this model's authoritative records.
func (m *Model) Open() session.Store { return &connection{model: m} }

// FailNext injects one failure into the next transaction that writes records.
func (m *Model) FailNext(failure Failure) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failNext = failure
}

type connection struct{ model *Model }

func (c *connection) Transact(ctx context.Context, scope session.Scope, fn func(session.Transaction) error) error {
	c.model.mu.Lock()
	defer c.model.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	tx := &transaction{data: copyPartition(c.model.data[scope])}
	if err := fn(tx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !tx.dirty {
		return nil
	}
	failure := c.model.failNext
	c.model.failNext = 0
	if failure == BeforeCommit {
		return ErrInjected
	}
	if c.model.data == nil {
		c.model.data = make(map[session.Scope]partition)
	}
	c.model.data[scope] = copyPartition(tx.data)
	if failure == AfterCommit {
		return ErrInjected
	}
	return nil
}

type transaction struct {
	data  partition
	dirty bool
}

func (tx *transaction) Key() (session.KeyRecord, bool, error) {
	return copyKey(tx.data.key), tx.data.hasKey, nil
}

func (tx *transaction) PutKey(key session.KeyRecord) error {
	tx.data.key = copyKey(key)
	tx.data.hasKey = true
	tx.dirty = true
	return nil
}

func (tx *transaction) Session(id session.ID) (session.Record, bool, error) {
	record, found := tx.data.sessions[id]
	return copyRecord(record), found, nil
}

func (tx *transaction) PutSession(id session.ID, record session.Record) error {
	tx.data.sessions[id] = copyRecord(record)
	tx.dirty = true
	return nil
}

func (tx *transaction) NonceUsed(id string) (bool, error) {
	return tx.data.nonces[id], nil
}

func (tx *transaction) UseNonce(id string) error {
	tx.data.nonces[id] = true
	tx.dirty = true
	return nil
}

func copyPartition(p partition) partition {
	out := partition{key: copyKey(p.key), hasKey: p.hasKey, sessions: make(map[session.ID]session.Record), nonces: make(map[string]bool)}
	for id, record := range p.sessions {
		out.sessions[id] = copyRecord(record)
	}
	for id, used := range p.nonces {
		out.nonces[id] = used
	}
	return out
}

func copyKey(key session.KeyRecord) session.KeyRecord {
	key.Checkpoint = slices.Clone(key.Checkpoint)
	key.Blacklist = slices.Clone(key.Blacklist)
	if key.Refresh != nil {
		pending := *key.Refresh
		pending.Checkpoint = slices.Clone(pending.Checkpoint)
		key.Refresh = &pending
	}
	return key
}

func copyRecord(record session.Record) session.Record {
	record.Checkpoint = slices.Clone(record.Checkpoint)
	record.Participants = slices.Clone(record.Participants)
	outputs := make(map[int][]byte, len(record.Outputs))
	for round, output := range record.Outputs {
		outputs[round] = slices.Clone(output)
	}
	record.Outputs = outputs
	return record
}
