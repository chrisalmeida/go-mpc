package session

import (
	"context"
	"slices"
	"sync"
)

type memoryID struct {
	Scope Scope
	ID    ID
	Round int
}

// Memory retains private operation checkpoints in one process. Its zero value is
// ready to use and must not be copied after first use. Persistent key checkpoints,
// outputs and progress still commit through Store. Close erases retained buffers;
// after process loss, abort pending InMemory operations and use fresh IDs.
type Memory struct {
	mu          sync.Mutex
	checkpoints map[memoryID][]byte
}

// Advance runs an InMemory operation through the ordinary transactional guard.
// A candidate checkpoint is retained before commit, including on an uncertain
// outcome, so a lost acknowledgement does not lose a committed round's state.
// The next request selects only state for the authoritative preceding round.
// A confirmed commit clears superseded checkpoints for this operation; uncertain
// outcomes retain candidates and preceding state until progress is confirmed.
// Compute must restore fresh objects; rolled-back candidates are never outputs.
// Memory takes ownership of Update.Checkpoint and clears its returned buffer.
func (m *Memory) Advance(ctx context.Context, store Store, scope Scope, req Request, compute Compute) (*Receipt, error) {
	if m == nil || compute == nil {
		return nil, ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	req.Mode = InMemory
	receipt, err := Advance(ctx, store, scope, req, func(in Input) (Update, error) {
		if in.Round > 1 {
			previous, ok := m.checkpoints[memoryID{scope, in.ID, in.Round - 1}]
			if !ok {
				return Update{}, ErrUnavailable
			}
			in.SessionCheckpoint = slices.Clone(previous)
			defer clear(in.SessionCheckpoint)
		}
		u, err := compute(in)
		if err != nil {
			clear(u.Checkpoint)
			return Update{}, err
		}
		if u.Abort != nil && len(u.Checkpoint) != 0 {
			clear(u.Checkpoint)
			return Update{}, ErrInvalid
		}
		terminal := in.Round == finalRound(scope.Protocol, in.ID.Kind)
		if u.Abort == nil && terminal != (len(u.Checkpoint) == 0) {
			clear(u.Checkpoint)
			return Update{}, ErrInvalid
		}
		if len(u.Checkpoint) > 0 {
			if m.checkpoints == nil {
				m.checkpoints = make(map[memoryID][]byte)
			}
			id := memoryID{scope, in.ID, in.Round}
			clear(m.checkpoints[id])
			m.checkpoints[id] = slices.Clone(u.Checkpoint)
			clear(u.Checkpoint)
			u.Checkpoint = nil
		}
		return u, nil
	})
	if err == nil {
		terminal := req.Round == finalRound(scope.Protocol, req.ID.Kind)
		for key, checkpoint := range m.checkpoints {
			if key.Scope == scope && key.ID == req.ID && (terminal || key.Round < req.Round) {
				clear(checkpoint)
				delete(m.checkpoints, key)
			}
		}
	}
	return receipt, err
}

func (m *Memory) forget(scope Scope, id ID) {
	for key, checkpoint := range m.checkpoints {
		if key.Scope == scope && key.ID == id {
			clear(checkpoint)
			delete(m.checkpoints, key)
		}
	}
}

// Forget erases locally retained state after an operation was durably aborted or
// completed. It does not alter progress; the caller must Abort separately.
func (m *Memory) Forget(scope Scope, id ID) { m.mu.Lock(); defer m.mu.Unlock(); m.forget(scope, id) }

// Close erases all retained private checkpoints. Pending operations then require
// Abort; closing this object cannot erase Store backups or historical disk blocks.
func (m *Memory) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, checkpoint := range m.checkpoints {
		clear(checkpoint)
		delete(m.checkpoints, id)
	}
}
