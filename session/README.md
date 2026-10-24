# session — transactional progress guard

Caller-side lifetime guard for the DKLS23 (Protocol 3.6) and FROST (RFC 9591 §5.1–5.2) rounds. It implements the persistence rules of [SECURITY.md](../SECURITY.md#session-lifetime-and-persistence) over a transactional store that **you** supply: at most one committed result per round, outputs cached for retransmission, nonce markers that surface cloned randomness, revision checks that reject stale backups, and a prepare/activate gate for refresh. It changes neither protocol, chooses no database, and defines no private-state format. See AUDIT.md FU-MED-6 for the finding it mitigates.

## Files

| File | Purpose |
| --- | --- |
| `store.go` | `Scope`, `ID`, `Version`, `KeyRecord`, `Record`; the `Store`/`Transaction` contract; `Request`, `Input`, `Update`, `Compute`; sentinel errors |
| `memory.go` | `Memory.Advance`, `Forget`, `Close`; operation checkpoints stay in process memory |
| `guard.go` | `Initialize`, `InspectKey`, `InspectSession`, `Advance`, `Output`, `Abort`, `Blacklist`, `Activate` |
| `storetest/contract.go` | `Run`: the conformance suite every `Store` adapter must pass under `-race` |
| `storetest/model.go` | `Model`: an in-memory store with injectable commit failures, for tests only |

## How a round runs

1. The application builds a `Request` naming the key `Version` it last observed, the operation `ID` (kind, epoch, value), the round, and the participants.
2. `Advance` opens one transaction, loads the key record, and rejects the request if the version is stale, a participant is blacklisted, the round is out of order, the participants changed, or a refresh is pending.
3. It hands the `Compute` callback owned copies of the key and session checkpoints. The callback decodes them, checks that party, public key and epoch match the `Scope`, runs the protocol round, and returns an `Update`: the re-encoded key, the next private checkpoint (empty on the final round), the exact outgoing bytes, and for signing round 1 the nonce marker (`R_i` for DKLS23, `D_i || E_i` for FROST).
4. `Advance` checks legacy raw reservations, reserves the SHA-256 digest of the nonce marker, records progress, caches the output, merges blacklist changes, bumps the revision, and commits all of it atomically. Only then does it return the bytes to send.
5. If a commit's acknowledgement is lost, `Output` returns the committed bytes without recomputing. A callback error or panic discards tentative writes and preserves previously committed records. After confirming rollback, a new explicit `Advance` call can compute that round again from freshly decoded checkpoints; `Compute` must have no external side effects or transmit output. `Update.Abort` commits the blacklist and marks the operation aborted while returning no output.

Refresh runs the same way with `Kind: Refresh`. It requires no open signing sessions, blocks signing while pending, and its final round only *prepares* the new key checkpoint. `Activate` promotes that checkpoint and increments the epoch after the application has agreed on activation with its peers.

## What it does and does not guarantee

Given a `Store` that satisfies the documented contract (serialized transactions per scope, atomic commit, no automatic callback retries), the guard ensures at most one committed result per operation and round, rejects an older backup once the authoritative record has moved, rejects reuse of a nonce marker for another signing round-1 result, and prevents refresh from interleaving with signing. Rolled-back attempts can be recomputed by a later explicit call; only committed outputs are available for retransmission. The guard cannot supply the backend's physical durability, authenticate peers or their messages, detect a store restored from an old snapshot together with the signer, or coordinate activation across the group.

## Testing an adapter

Call `storetest.Run(t, factory)` with a factory that opens an isolated store and returns a function that reopens the same committed data. It checks that both `InMemory` and the zero-valued `Resumable` mode survive reopening. Its error and panic cases test both empty and populated storage: rollback must preserve the complete committed key and session records, cached outputs and nonce reservations while discarding replacements and new records. Passing this finite suite is necessary; it does not establish every part of the contract or the backend's physical durability. Test the deployment's actual crash and recovery behavior separately. `TestConformanceRejectsDroppedMode` verifies that an adapter which discards the mode fails the suite.

`dkls23/store_test.go` and `frost/store_test.go` drive complete signing sessions through `Advance` against `storetest.Model`, including a lost commit acknowledgement and concurrent calls; the DKLS23 test also rejects a stale backup. This repository ships no production backend.

## Library codecs, cold devices and online mode

Use `dkls23.SessionCodec` or `frost.SessionCodec` for the production checkpoint
format instead of defining a private DTO. Initialize with `MarshalEncrypted`
(DKLS23 setup) or `MarshalSignerEncrypted` (FROST signer), then pass the codec's
`Signing` or `Refresh` callback to `Advance`. Codecs decode fresh objects from
`Input`, validate scope/epoch/participants/phase and persist bound encrypted state.
A bare FROST `KeyShare` does not retain epoch or blacklist; use `SignerState`.

Codec `Receipt.Output` and cached `Record.Outputs` are **encrypted outbound
containers**. Open them after commit with `codec.OpenOutput(blob, trustedBinding,
operationID, round)`, then decode the ordinary protocol message. Refresh round 2
contains secret share updates: `OpenRefreshRound2` provides a typed decoder, and
each peer's share must travel over its authenticated confidential channel.
The guard itself accepts opaque bytes; caller-written callbacks must provide
whatever encryption their outputs require. A cached ciphertext is retransmitted
without recomputing or re-encrypting its protocol round.

For cold devices that power down, `Request.Mode` defaults to `Resumable`. Each
round checkpoint survives through the backend. Restore the same trusted scope
and progress on the next process/device; no object/process identity is checked.
For online operation, call `memory.Advance` on a retained `session.Memory` object.
This sets `InMemory`, stores no private round checkpoint, and still commits key
state, encrypted outputs and the nonce reservation. It keeps candidate state
through uncertain commits so the authoritative preceding round selects the
correct checkpoint. After a confirmed commit, it clears superseded checkpoint
buffers for that operation; final success clears all of its retained checkpoints.
Other scopes and operations are unaffected. Once Memory is lost or closed, `ErrUnavailable` requires an
explicit `Abort`; `Forget` clears local state after abort and `Close` clears all
retained buffers. Old record modes decode as the resumable zero value.
`TestMemoryModeClearsSupersededCheckpointsOnlyAfterConfirmedCommit` checks buffer
clearing, before/after-commit failures, continuation from the authoritative round,
and isolation of other operations and scopes. This is best-effort clearing of
the retained Go buffers, not proof of physical memory erasure.

Backend migrations must preserve `Record.Mode`, retained operation records and
legacy nonce reservations. New nonce reservation keys are 32-byte SHA-256 digests;
`Update.NonceID` continues to carry raw `R_i` or `D_i || E_i`. Never invent random
nonce IDs or delete old raw reservations during migration.

Both packages' `session_codec_test.go` complete encrypted signing and refresh
across reopened connections, verify signatures independently, reject sequential
and concurrent duplicate rounds, and recover a lost commit acknowledgement.
`example/shared` supplies a Linux/macOS file adapter and passes `storetest.Run`
plus kill-before/after-rename and concurrent-process tests. This example assumes
a trusted private directory and local filesystem semantics; it is not a production
storage certification, and it cannot detect whole-store snapshot rollback.
