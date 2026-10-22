package session

import (
	"context"
	"fmt"
	"math"
	"slices"
	"sync/atomic"
)

// Initialize installs a key checkpoint only in a previously unused Scope.
// Validate its key and epoch before this call; it never replaces existing
// progress with a signer backup.
func Initialize(ctx context.Context, store Store, scope Scope, epoch int, checkpoint []byte) (Version, error) {
	if epoch < 0 || len(checkpoint) == 0 {
		return Version{}, ErrInvalid
	}
	v := Version{Epoch: epoch, Revision: 1}
	err := transact(ctx, store, scope, func(tx Transaction) error {
		_, found, err := tx.Key()
		if err != nil {
			return err
		}
		if found {
			return ErrInitialized
		}
		return tx.PutKey(KeyRecord{Version: v, Checkpoint: slices.Clone(checkpoint)})
	})
	if err != nil {
		return Version{}, err
	}
	return v, nil
}

// InspectKey reads an owned copy of the authoritative key checkpoint and Version.
// The codec must also validate the contents of the opaque checkpoint.
func InspectKey(ctx context.Context, store Store, scope Scope) (KeyRecord, error) {
	var key KeyRecord
	err := transact(ctx, store, scope, func(tx Transaction) (err error) { key, err = loadKey(tx); return err })
	if err != nil {
		return KeyRecord{}, err
	}
	return key, nil
}

// InspectSession reads the latest checkpoint and cached outputs. Earlier epochs
// remain readable, but Advance requires the current epoch. Completion and abort
// remove the private operation checkpoint.
func InspectSession(ctx context.Context, store Store, scope Scope, id ID) (Record, error) {
	if !validID(id) {
		return Record{}, ErrInvalid
	}
	var record Record
	err := transact(ctx, store, scope, func(tx Transaction) error {
		if _, err := loadKey(tx); err != nil {
			return err
		}
		var found bool
		var err error
		record, found, err = loadSession(tx, scope, id)
		if err != nil {
			return err
		}
		if !found {
			return ErrMissing
		}
		return nil
	})
	if err != nil {
		return Record{}, err
	}
	return record, nil
}

// Advance computes the next round and commits checkpoints, nonce marker, public
// output, blacklist changes and progress in one transaction. Replays, stale
// versions and changed participant sets are rejected before Compute. These are
// caller-side lifetime guards for DKLS23 Protocol 3.6 and RFC 9591 Sections
// 5.1–5.2, not changes to either cryptographic protocol.
// At most one result commits for each operation and round. Rolled-back attempts
// can be recomputed by a later explicit call using freshly decoded checkpoints.
//
// Refresh requires no open signing sessions, then blocks signing until explicit
// activation or abort. Local finalization saves a candidate for Activate, which
// the application calls only after coordinating agreement with peers.
func Advance(ctx context.Context, store Store, scope Scope, req Request, compute Compute) (*Receipt, error) {
	if !validID(req.ID) || req.Epoch != req.ID.Epoch || req.Revision == 0 || req.Round < 1 || req.Round > finalRound(scope.Protocol, req.ID.Kind) || compute == nil {
		return nil, ErrInvalid
	}
	participants, err := partySet(req.Participants, scope.PartyID)
	if err != nil {
		return nil, err
	}
	req.Participants = participants
	var receipt Receipt
	var aborted error
	err = transact(ctx, store, scope, func(tx Transaction) error {
		key, err := loadVersion(tx, req.Version)
		if err != nil {
			return err
		}
		for _, id := range participants {
			if slices.Contains(key.Blacklist, id) {
				return ErrBlacklisted
			}
		}
		record, found, err := loadSession(tx, scope, req.ID)
		if err != nil {
			return err
		}
		if !found {
			if req.Round != 1 {
				return ErrProgress
			}
			record = Record{Participants: slices.Clone(participants), Outputs: make(map[int][]byte)}
		} else {
			if record.Aborted {
				return ErrAborted
			}
			if record.Completed || record.Round+1 != req.Round {
				return ErrProgress
			}
			if !slices.Equal(record.Participants, participants) {
				return ErrInvalid
			}
		}
		if req.ID.Kind == Signing {
			if key.Refresh != nil {
				return ErrBusy
			}
			if (!found && key.ActiveSessions == math.MaxUint64) || (found && key.ActiveSessions == 0) {
				return ErrCorrupt
			}
		} else {
			if key.ActiveSessions != 0 || key.Epoch == math.MaxInt {
				return ErrBusy
			}
			if !found && key.Refresh != nil {
				return ErrBusy
			}
			if found && (key.Refresh == nil || key.Refresh.SessionID != req.ID.Value || key.Refresh.Prepared) {
				return ErrCorrupt
			}
		}
		if key.Revision == math.MaxUint64 {
			return ErrCorrupt
		}
		input := Input{Scope: scope, Request: req, KeyCheckpoint: slices.Clone(key.Checkpoint), SessionCheckpoint: slices.Clone(record.Checkpoint)}
		input.Participants = slices.Clone(participants)
		u, err := compute(input)
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(u.KeyCheckpoint) == 0 {
			return ErrInvalid
		}
		if u.Abort != nil {
			if len(u.Output) != 0 || len(u.Checkpoint) != 0 || u.NonceID != "" {
				return ErrInvalid
			}
			record.Aborted = true
			record.Checkpoint = nil
			if req.ID.Kind == Signing && found {
				key.ActiveSessions--
			}
			if req.ID.Kind == Refresh {
				key.Refresh = nil
			}
			key.Checkpoint = slices.Clone(u.KeyCheckpoint)
			aborted = u.Abort
		} else {
			terminal := req.Round == finalRound(scope.Protocol, req.ID.Kind)
			if terminal != (len(u.Checkpoint) == 0) {
				return ErrInvalid
			}
			if len(u.Output) == 0 && !(terminal && req.ID.Kind == Refresh) {
				return ErrInvalid
			}
			if req.ID.Kind == Signing && req.Round == 1 {
				width := 64
				if scope.Protocol == DKLS23 {
					width = 33
				}
				if len(u.NonceID) != width {
					return ErrInvalid
				}
				used, err := tx.NonceUsed(u.NonceID)
				if err != nil {
					return err
				}
				if used {
					return ErrNonceUsed
				}
				if err := tx.UseNonce(u.NonceID); err != nil {
					return err
				}
			} else if u.NonceID != "" {
				return ErrInvalid
			}
			record.Round = req.Round
			record.Completed = terminal
			record.Checkpoint = slices.Clone(u.Checkpoint)
			record.Outputs[req.Round] = slices.Clone(u.Output)
			if req.ID.Kind == Signing {
				if !found {
					key.ActiveSessions++
				}
				if terminal {
					key.ActiveSessions--
				}
				key.Checkpoint = slices.Clone(u.KeyCheckpoint)
			} else if terminal {
				key.Refresh.Prepared = true
				key.Refresh.Checkpoint = slices.Clone(u.KeyCheckpoint)
			} else {
				key.Checkpoint = slices.Clone(u.KeyCheckpoint)
				key.Refresh = &PendingRefresh{SessionID: req.ID.Value}
			}
		}
		key.Blacklist, err = mergeBlacklist(key.Blacklist, u.Blacklist)
		if err != nil {
			return err
		}
		key.Revision++
		if err := tx.PutKey(cloneKey(key)); err != nil {
			return err
		}
		if err := tx.PutSession(req.ID, cloneRecord(record)); err != nil {
			return err
		}
		receipt = Receipt{Version: key.Version, Output: slices.Clone(u.Output)}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if aborted != nil {
		return nil, fmt.Errorf("session Advance: aborted after committing progress: %w", aborted)
	}
	return &receipt, nil
}

// Output recovers identical completed-round bytes after a lost commit
// acknowledgement without rerunning a round or changing progress. It does not
// authorize sending those bytes on another session.
func Output(ctx context.Context, store Store, scope Scope, id ID, round int) ([]byte, error) {
	if round < 1 || round > finalRound(scope.Protocol, id.Kind) {
		return nil, ErrInvalid
	}
	record, err := InspectSession(ctx, store, scope, id)
	if err != nil {
		return nil, err
	}
	output, found := record.Outputs[round]
	if !found {
		return nil, ErrMissing
	}
	return slices.Clone(output), nil
}

// Abort abandons a pending operation, retains its spent identifier and public
// outputs, and removes its private checkpoint. Aborting a refresh requires an
// application-coordinated decision, particularly if peers might have activated.
func Abort(ctx context.Context, store Store, scope Scope, version Version, id ID) (Version, error) {
	if !validID(id) || id.Epoch != version.Epoch {
		return Version{}, ErrInvalid
	}
	var next Version
	err := transact(ctx, store, scope, func(tx Transaction) error {
		key, err := loadVersion(tx, version)
		if err != nil {
			return err
		}
		record, found, err := loadSession(tx, scope, id)
		if err != nil {
			return err
		}
		if !found {
			return ErrMissing
		}
		if record.Aborted {
			return ErrAborted
		}
		if id.Kind == Signing {
			if record.Completed {
				return ErrProgress
			}
			if key.ActiveSessions == 0 {
				return ErrCorrupt
			}
			key.ActiveSessions--
		} else {
			if key.Refresh == nil || key.Refresh.SessionID != id.Value {
				return ErrCorrupt
			}
			key.Refresh = nil
		}
		record.Completed = false
		record.Aborted = true
		record.Checkpoint = nil
		if err := bump(&key); err != nil {
			return err
		}
		if err := tx.PutSession(id, record); err != nil {
			return err
		}
		if err := tx.PutKey(key); err != nil {
			return err
		}
		next = key.Version
		return nil
	})
	if err != nil {
		return Version{}, err
	}
	return next, nil
}

// Blacklist durably retains caller-authorized policy decisions. FROST RFC 9591
// Section 5.4's attribution assumptions remain the caller's responsibility;
// this function never infers blame from a coordinator's error report.
func Blacklist(ctx context.Context, store Store, scope Scope, version Version, parties []int) (Version, error) {
	var next Version
	err := transact(ctx, store, scope, func(tx Transaction) error {
		key, err := loadVersion(tx, version)
		if err != nil {
			return err
		}
		key.Blacklist, err = mergeBlacklist(key.Blacklist, parties)
		if err != nil {
			return err
		}
		if err := bump(&key); err != nil {
			return err
		}
		if err := tx.PutKey(key); err != nil {
			return err
		}
		next = key.Version
		return nil
	})
	if err != nil {
		return Version{}, err
	}
	return next, nil
}

// Activate promotes a locally prepared refresh checkpoint and increments the
// epoch. Call only after coordinating activation with the group and preventing
// mixed-epoch signing. This is a local guard, not a distributed commit protocol.
func Activate(ctx context.Context, store Store, scope Scope, version Version, sessionID string) (Version, error) {
	if sessionID == "" {
		return Version{}, ErrInvalid
	}
	var next Version
	err := transact(ctx, store, scope, func(tx Transaction) error {
		key, err := loadVersion(tx, version)
		if err != nil {
			return err
		}
		if key.Refresh == nil || key.Refresh.SessionID != sessionID || !key.Refresh.Prepared {
			return ErrProgress
		}
		record, found, err := loadSession(tx, scope, ID{Kind: Refresh, Epoch: key.Epoch, Value: sessionID})
		if err != nil {
			return err
		}
		if !found || !record.Completed || record.Aborted || key.ActiveSessions != 0 || key.Epoch == math.MaxInt {
			return ErrCorrupt
		}
		key.Checkpoint = slices.Clone(key.Refresh.Checkpoint)
		key.Refresh = nil
		key.Epoch++
		if err := bump(&key); err != nil {
			return err
		}
		if err := tx.PutKey(key); err != nil {
			return err
		}
		next = key.Version
		return nil
	})
	if err != nil {
		return Version{}, err
	}
	return next, nil
}

func transact(ctx context.Context, store Store, scope Scope, fn func(Transaction) error) error {
	if ctx == nil || store == nil || !validScope(scope) {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var calls atomic.Int32
	err := store.Transact(ctx, scope, func(tx Transaction) error {
		if calls.Add(1) != 1 || tx == nil {
			return ErrStoreContract
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return fn(tx)
	})
	if err != nil {
		return fmt.Errorf("session transaction: %w", err)
	}
	if calls.Load() != 1 {
		return ErrStoreContract
	}
	return nil
}

func loadKey(tx Transaction) (KeyRecord, error) {
	key, found, err := tx.Key()
	if err != nil {
		return KeyRecord{}, err
	}
	if !found {
		return KeyRecord{}, ErrMissing
	}
	if key.Epoch < 0 || key.Revision == 0 || len(key.Checkpoint) == 0 {
		return KeyRecord{}, ErrCorrupt
	}
	parties, err := mergeBlacklist(nil, key.Blacklist)
	if err != nil || !slices.Equal(parties, key.Blacklist) {
		return KeyRecord{}, ErrCorrupt
	}
	if pending := key.Refresh; pending != nil {
		if pending.SessionID == "" || pending.Prepared != (len(pending.Checkpoint) != 0) || key.ActiveSessions != 0 {
			return KeyRecord{}, ErrCorrupt
		}
	}
	return cloneKey(key), nil
}

func loadVersion(tx Transaction, version Version) (KeyRecord, error) {
	key, err := loadKey(tx)
	if err != nil {
		return KeyRecord{}, err
	}
	if key.Version != version {
		return KeyRecord{}, ErrStale
	}
	return key, nil
}

func loadSession(tx Transaction, scope Scope, id ID) (Record, bool, error) {
	record, found, err := tx.Session(id)
	if err != nil || !found {
		return Record{}, found, err
	}
	last := finalRound(scope.Protocol, id.Kind)
	parties, err := partySet(record.Participants, scope.PartyID)
	if err != nil || !slices.Equal(parties, record.Participants) || record.Round < 0 || record.Round > last ||
		(record.Completed && record.Aborted) || (record.Round == 0 && !record.Aborted) ||
		(!record.Aborted && record.Completed != (record.Round == last)) ||
		((record.Aborted || record.Completed) != (len(record.Checkpoint) == 0)) || len(record.Outputs) != record.Round {
		return Record{}, true, ErrCorrupt
	}
	for round := 1; round <= record.Round; round++ {
		output, exists := record.Outputs[round]
		if !exists || (len(output) == 0 && !(id.Kind == Refresh && round == last)) {
			return Record{}, true, ErrCorrupt
		}
	}
	return cloneRecord(record), true, nil
}

func validScope(scope Scope) bool {
	if scope.PartyID < 1 || scope.PartyID > math.MaxInt32 {
		return false
	}
	return (scope.Protocol == DKLS23 && len(scope.PublicKey) == 33) || (scope.Protocol == FROST && len(scope.PublicKey) == 32)
}
func validID(id ID) bool {
	return (id.Kind == Signing || id.Kind == Refresh) && id.Epoch >= 0 && id.Value != ""
}
func finalRound(protocol Protocol, kind Kind) int {
	if kind == Refresh {
		return 3
	}
	if protocol == FROST {
		return 2
	}
	return 3
}
func partySet(parties []int, own int) ([]int, error) {
	if len(parties) == 0 {
		return nil, ErrInvalid
	}
	out := slices.Clone(parties)
	slices.Sort(out)
	for i, id := range out {
		if id < 1 || id > math.MaxInt32 || (i > 0 && out[i-1] == id) {
			return nil, ErrInvalid
		}
	}
	if !slices.Contains(out, own) {
		return nil, ErrInvalid
	}
	return out, nil
}
func mergeBlacklist(a, b []int) ([]int, error) {
	out := append(slices.Clone(a), b...)
	slices.Sort(out)
	for _, id := range out {
		if id < 1 || id > math.MaxInt32 {
			return nil, ErrInvalid
		}
	}
	return slices.Compact(out), nil
}
func bump(key *KeyRecord) error {
	if key.Revision == math.MaxUint64 {
		return ErrCorrupt
	}
	key.Revision++
	return nil
}
func cloneKey(key KeyRecord) KeyRecord {
	key.Checkpoint = slices.Clone(key.Checkpoint)
	key.Blacklist = slices.Clone(key.Blacklist)
	if key.Refresh != nil {
		pending := *key.Refresh
		pending.Checkpoint = slices.Clone(pending.Checkpoint)
		key.Refresh = &pending
	}
	return key
}
func cloneRecord(record Record) Record {
	record.Checkpoint = slices.Clone(record.Checkpoint)
	record.Participants = slices.Clone(record.Participants)
	outputs := make(map[int][]byte, len(record.Outputs))
	for round, output := range record.Outputs {
		outputs[round] = slices.Clone(output)
	}
	record.Outputs = outputs
	return record
}
