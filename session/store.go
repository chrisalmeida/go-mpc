// Package session supplies caller-side transactional progress guards for DKLS23
// Protocol 3.6 and FROST RFC 9591 Sections 5.1–5.2. It does not change either
// cryptographic protocol, choose a database, or choose a private-state format.
//
// Store implementations must provide the transaction and durability properties
// documented below. In particular, keep their progress records independently of
// signer backups. Restoring both the database and the signer to an old snapshot
// defeats a progress guard. session/storetest exercises the storage contract;
// deployment-specific crash and rollback testing is still required.
package session

import (
	"context"
	"errors"
)

// Protocol identifies the cryptographic protocol whose local progress is stored.
type Protocol string

const (
	// DKLS23 identifies DKLS23 Protocol 3.6 signing and the package's KMOS21 refresh.
	DKLS23 Protocol = "dkls23"
	// FROST identifies RFC 9591 signing and the package's FROST share refresh.
	FROST Protocol = "frost"
)

// Scope separates one participant's records for one group public key. PublicKey
// contains canonical encoded public-key bytes converted to a string, not hex.
// The checkpoint codec must validate that decoded keys match this scope and
// Version before calling a cryptographic round. These fields are local storage
// identifiers; they are not additions to a protocol message or hash transcript.
type Scope struct {
	Protocol  Protocol
	PublicKey string
	PartyID   int
}

// Kind distinguishes signing and refresh progress in local storage.
type Kind string

const (
	// Signing tracks DKLS23's three rounds or FROST's two rounds.
	Signing Kind = "signing"
	// Refresh tracks refresh round 1, round 2, and local finalization.
	Refresh Kind = "refresh"
)

// ID identifies an operation within a Scope. Epochs are retained in operation
// keys so a refresh can make a DKLS23 signing identifier fresh without overwriting
// its old progress. Authenticate peer routing against the same session context;
// this identifier alone does not authenticate peer messages.
type ID struct {
	Kind  Kind
	Epoch int
	Value string
}

// Version is the epoch and monotonic local revision of the authoritative key
// record. Keep it with backups; operations carrying an older revision are rejected.
type Version struct {
	Epoch    int
	Revision uint64
}

// PendingRefresh records a local refresh awaiting caller-coordinated activation.
// Checkpoint is populated only after successful local finalization. While this
// record exists, signing is blocked. It does not establish agreement with peers.
type PendingRefresh struct {
	SessionID  string
	Prepared   bool
	Checkpoint []byte
}

// KeyRecord holds the current caller-encoded key checkpoint and local progress.
// Checkpoints can contain secrets: the caller must protect them and supply a
// codec that validates scope, epoch, and private state. Blacklist contains retained
// policy decisions; this package never derives blame from a protocol error.
type KeyRecord struct {
	Version
	Checkpoint     []byte
	Blacklist      []int
	ActiveSessions uint64
	Refresh        *PendingRefresh
}

// Mode selects whether an operation's private checkpoint survives a process
// restart. The zero value preserves the existing resumable behavior.
type Mode string

const (
	// Resumable persists encrypted operation checkpoints between rounds.
	Resumable Mode = ""
	// InMemory retains operation checkpoints only in a session.Memory instance.
	// After losing that instance the pending operation can only be aborted.
	InMemory Mode = "memory"
)

// Record holds an operation's latest private checkpoint and cached outgoing bytes.
// Protocol codecs encrypt confidential refresh outputs before returning them.
// Outputs retain each completed round's encoded bytes for identical retransmission after
// a crash. Completion or explicit abort removes the latest private checkpoint;
// the Store's physical erasure and historical copies remain the caller's concern.
type Record struct {
	Mode         Mode
	Round        int
	Participants []int
	Checkpoint   []byte
	Outputs      map[int][]byte
	Completed    bool
	Aborted      bool
}

// Store is a caller-supplied transaction boundary. Transact must:
//   - serialize transactions for the complete Scope, including across processes;
//   - call fn synchronously and at most once, with an isolated writable view;
//   - atomically commit all writes only when fn returns nil;
//   - discard tentative writes on callback error or panic, preserve previously
//     committed records, then propagate the panic;
//   - return nil only after committed writes survive the failures the deployment
//     claims to tolerate; return an error when the commit outcome is uncertain.
//
// Automatic callback retries are forbidden: callbacks can consume cryptographic
// state. On any transaction error, callers receive no output from Advance. Inspect
// the authoritative records and use Output to recover a committed result instead
// of rerunning a completed round. Transact must honor cancellation before commit.
// No interface can enforce these properties on an incorrectly implemented backend.
type Store interface {
	Transact(ctx context.Context, scope Scope, fn func(Transaction) error) error
}

// Transaction accesses records inside Store.Transact. Missing records return
// found=false and err=nil. Reads return owned copies; writes copy their arguments.
// Retain operation records, including Record.Mode, and nonce records across
// restarts and signer restoration.
// Nonce markers are scoped to the key and party, not to an epoch. New markers
// are SHA-256 digests; existing raw reservations remain readable for migration.
// Treat progress, outputs and checkpoints as confidential application data.
type Transaction interface {
	Key() (record KeyRecord, found bool, err error)
	PutKey(record KeyRecord) error
	Session(id ID) (record Record, found bool, err error)
	PutSession(id ID, record Record) error
	NonceUsed(id string) (used bool, err error)
	UseNonce(id string) error
}

// Request selects exactly the next local round using an authoritative Version.
// Participants is a set of positive, distinct party IDs including Scope.PartyID.
// Advance sorts a copy for storage only; it does not encode protocol transcripts.
type Request struct {
	Mode Mode
	Version
	ID           ID
	Round        int
	Participants []int
}

// Input contains owned copies of the authoritative checkpoints for Compute.
// Decode these copies rather than reusing objects from a signer backup. Validate
// their key, epoch, participants, phase and encodings before invoking a round.
// Compute must have no external side effects and must not transmit any output.
type Input struct {
	Scope Scope
	Request
	KeyCheckpoint     []byte
	SessionCheckpoint []byte
}

// Update is a computed round awaiting atomic persistence. KeyCheckpoint is the
// updated caller-encoded key state, including protocol progress and blacklist
// changes. Checkpoint holds this operation's private state for its next round;
// final rounds require it to be empty. Output is the exact outgoing encoding.
//
// Signing round 1 also supplies NonceID: DKLS23's encoded R_i, or FROST's encoded
// D_i || E_i. Derive it from the generated state, never from a caller-chosen random
// identifier. Advance stores its SHA-256 digest and also checks legacy raw
// reservations. Repeating it is rejected even under another session/epoch.
//
// Abort can report a terminal protocol error while atomically recording the
// updated key and any caller-authorized Blacklist entries. An aborted update
// carries no output or private operation checkpoint. Ordinary Compute errors
// roll back the transaction and leave the session retryable.
type Update struct {
	KeyCheckpoint []byte
	Checkpoint    []byte
	Output        []byte
	NonceID       string
	Blacklist     []int
	Abort         error
}

// Compute runs a cryptographic round against Input's restored checkpoints. The
// codec and the round implementation remain the caller's; Advance commits their
// result and progress together before returning any bytes for transmission.
// After rollback, a later explicit Advance call can run Compute again for the
// same round. Each invocation must decode fresh checkpoints and have no external
// side effects, as required by Input.
type Compute func(Input) (Update, error)

// Receipt is returned only after a confirmed commit. A final refresh receipt
// means prepared locally; the caller still coordinates group activation.
type Receipt struct {
	Version
	Output []byte
}

var (
	ErrInvalid       = errors.New("session: invalid request")
	ErrMissing       = errors.New("session: missing record")
	ErrInitialized   = errors.New("session: key already initialized")
	ErrStale         = errors.New("session: stale version")
	ErrProgress      = errors.New("session: round already used or out of order")
	ErrAborted       = errors.New("session: operation aborted")
	ErrBlacklisted   = errors.New("session: participant is blacklisted")
	ErrNonceUsed     = errors.New("session: nonce marker already used")
	ErrBusy          = errors.New("session: signing or refresh is still pending")
	ErrCorrupt       = errors.New("session: corrupt progress record")
	ErrUnavailable   = errors.New("session: in-memory checkpoint unavailable; abort the operation")
	ErrStoreContract = errors.New("session: store violated callback contract")
)
