# Encrypted state and cold signing — design note

**Status**: proposal for maintainer review, 2026-10-21. Nothing in this note is
implemented yet. It complements [SECURITY.md](../SECURITY.md#session-lifetime-and-persistence),
[session/README.md](../session/README.md) and AUDIT.md FU-MED-6, and it changes
no protocol message, hash input, security parameter or test vector.

## Goals

1. Every secret the library asks a caller to persist has a library-provided
   encoding and an encrypted wrapper. Applications never define a private-state
   format of their own.
2. An encrypted blob is bound to its context: protocol, blob kind, wire
   version, group public key, party id, key epoch, and for session checkpoints
   the operation id and round. A blob cannot be presented as another party's,
   epoch's, operation's or round's state.
3. Cold signing is a supported mode, not an afterthought. A signer may be
   powered off between rounds and resume later from encrypted state.
4. The library still chooses no cipher, holds no key, and ships no storage
   backend. These remain the caller's.

Non-goals: key custody and rotation policy (caller), physical durability
(backend), memory protection beyond best-effort zeroization, and any change to
the protocols themselves.

## Terminology

- **Online signer**: a long-running process with a network connection; rounds
  complete within seconds.
- **Cold signer**: an air-gapped device; messages cross by file or QR code and
  the device may power down between rounds.
- **Resumable mode**: private round state is persisted (encrypted) between
  rounds. This is what the session guard does today.
- **In-memory mode**: private round state lives only in process memory; a
  restart aborts the session. New, proposed default for online signers.
- **Envelope**: the encrypted container described in section 1.

## 1. Envelope package

A new package `envelope` owns the container format. The two protocol packages
and the session codecs use it; it imports neither.

**Encryptor interface.** Unchanged shape: encrypt bytes to bytes, decrypt bytes
to bytes. `dkls23.SetupEncryptor` and `frost.SetupEncryptor` become aliases of
`envelope.Encryptor`, so existing implementations keep compiling. An optional
second interface, `ContextEncryptor`, adds an associated-data parameter; when an
encryptor implements it, the envelope passes the clear header as associated
data. This is the hook for AEAD ciphers and for KMS products whose encryption
context is authenticated server-side. The binding below does not depend on it.

**Context.** A struct with the fields: protocol tag, blob kind, wire version,
group public key bytes, party id, epoch, operation id (empty for key material),
round (zero for key material). Encoded canonically as length-prefixed fields in
declaration order. The library composes it; callers never type it by hand.

**Blob layout.**

```
byte 0        envelope format version (1)
bytes 1–2     context length, big-endian
context       canonical context bytes, in clear
ciphertext    Encrypt(context || plaintext)
```

**Operations.**

- `Seal(enc, ctx, plaintext)` builds the blob above.
- `Open(enc, expect, blob)` parses the header, compares the clear context with
  the caller's expectation in constant time and refuses to decrypt on mismatch,
  decrypts, compares the embedded copy with the expectation again, and returns
  the plaintext. Every failure is a typed error naming which field disagreed.
- `Peek(blob)` returns the clear header context without decrypting. It is
  public metadata for manifests and routing; it is not trusted until `Open`
  confirms it against the embedded copy.

**Why a clear header and an embedded copy.** The header makes blobs
self-describing for operators and lets `Open` refuse foreign blobs before
touching the key. The embedded copy makes the binding hold even for encryptors
without associated-data support, and detects a header spliced onto another
ciphertext. When the encryptor does support associated data the header is also
authenticated by the cipher; the three checks agree or the blob is rejected.

**What this does and does not defend against.** It stops a blob from being
loaded as the wrong party, epoch, operation or round, which is the association
FU-MED-6 found missing from the persisted formats, and it does so without
changing those formats. It does nothing against an attacker who holds the
encryption key, and it does not detect rollback to an older blob of the same
context; the session guard's revision check covers that.

## 2. Encodings and wrappers

| Protocol | State | Today | Planned |
| --- | --- | --- | --- |
| dkls23 | `SignerSetup` | JSON; encrypted wrapper without binding | Bound envelope, kind `setup` |
| dkls23 | `Round1State`, `Round2State` | JSON only | Bound envelopes, kinds `sign-1`, `sign-2`; context carries session id and round |
| dkls23 | Refresh coefficients and seed | No encoding | Strict JSON and bound envelopes, kinds `refresh-1`, `refresh-2` (needed for cold refresh) |
| frost | `KeyShare` | JSON; encrypted wrapper without binding | Bound envelope, kind `key` |
| frost | `SignerState` | JSON only | Bound envelope, kind `signer` |
| frost | `Round1State` (nonces) | No encoding | Strict JSON (canonical scalars, commitment, signers) and bound envelope, kind `sign-1`; a restored state receives a fresh single-use record |
| frost | Refresh coefficients and seed | No encoding | Strict JSON and bound envelope, kinds `refresh-1`, `refresh-2` |

Rules that apply to every new encoding, from CLAUDE.md: strict `UnmarshalJSON`
with receiver preservation, a fuzz target, an unmarshal error table, and
rejection tests for each context field. The encrypted `Unmarshal*` functions
gain an expected-binding parameter; this is a breaking signature change,
recorded in the README upgrading section. Callers that do not yet know a blob's
binding use `Peek` and then validate what they learn against their own records.

## 3. Session guard modes

- **Resumable mode** is the current behaviour and stays the mode for cold
  devices that power down: the codec encrypts the round checkpoint, the guard
  commits it with the progress record and nonce marker, and deletes it when the
  round completes. One use per round is enforced by the progress record even
  after a restart.
- **In-memory mode** is new: the guard accepts an empty round checkpoint while
  an operation is open, and after a restart the only permitted action on that
  operation is `Abort`. Nothing ephemeral reaches storage. It becomes the
  documented default for online signers; the codec chooses the mode per
  operation.
- **Nonce marker** becomes a 32-byte digest of the committed nonce point(s)
  instead of the raw encoding, so the store's plaintext index never holds a
  value the protocol has not yet revealed. Uniqueness is unaffected.
- **Refresh interaction.** FROST round-1 state is already bound to the key
  epoch, and the guard already refuses to start a refresh while operations are
  open. Pre-generated commitments must therefore be consumed or aborted before
  `Activate`; the cold-signing flow below says so explicitly.

## 4. Cold signing flows

**Mode A, device stays powered between transfers.** Rounds run in one process;
in-memory mode applies. A crash or power loss aborts the session and the group
starts a new one. Safe, occasionally inconvenient.

**Mode B, device powers down between rounds.** Resumable mode applies. For each
round: `Advance` runs the round and commits the encrypted checkpoint, the
output is exported by file or QR, the device powers down; later the peers'
messages are imported and `Advance` runs the next round from the committed
checkpoint. The envelope binding guarantees the checkpoint belongs to this
scope, epoch, operation and round; the guard guarantees it is used once.

**FROST with pre-generated commitments.** The FROST paper's preprocessing
variant lets a cold device run round 1 for many operations in one powered
session and export all commitments. Each is an ordinary operation stopped after
round 1; later, one is completed with the message. This requires resumable
mode and the guard's single-use enforcement, and all unused operations must be
aborted before a refresh is activated. RFC 9591's own description is purely
online; the paper is the cited source for this construction.

**DKLS23.** Three interactive rounds with persisted state between transfers.
The paper's §3.3 defines two ways to move work ahead of the message, and the
implementation already supplies the message only at round 3, so both need no
code change (AUDIT.md FU-LOW-8):

- *Pipelining*: round 1 runs before the message. The nonce R is fixed only in
  round 2, so the standard security argument holds under the paper's revised
  functionality. Acceptable generally; for a cold device it saves one powered
  exchange.
- *Pre-signing*: rounds 1 and 2 run before the message, leaving a single
  exchange at signing time. The paper says the protocol is compatible with it
  but that security then rests on Groth and Shoup's stronger assumption, and it
  warns that only those who accept that risk should use it. It is an explicit
  opt-in here. A stored round-2 state is nonce material: it completes exactly
  one message, never rests unencrypted, is consumed or aborted before a
  refresh, and is never shared between copies. Pre-signing must be re-examined
  before any key-derivation feature is ever added, which the Groth and Shoup
  analysis singles out.

**Transport sizes.** FROST messages are tens of bytes and suit QR codes. DKLS23
round-1 and round-2 messages are tens of kilobytes per counterparty and need
removable media or multi-part QR; a compact binary encoding is out of scope for
this work.

**Device policy.** The store and the signer must be backed up and restored
together or not at all; the guard cannot detect a store restored from an old
snapshot alongside the signer. A file-backed store with write-to-temporary,
sync and rename under a directory lock is the recommended backend for a device
without a database.

## 5. Store and demos

- A file-backed `Store` that passes `storetest.Run` under the race detector and
  a kill-during-commit test. First in `example/shared`; promotion into the
  library is a maintainer decision.
- Both demos driven through the session package with the library codecs.
- A FROST cold-signing demo: two directories exchanging message files, with
  power-off simulated by a process restart between rounds.
- The example encryptor gains envelope encryption: a wrapping key from the
  environment or OS keychain protects a data key, the data key encrypts
  checkpoints, and a key identifier in the encryptor's own header allows
  rotation. Because every round re-encrypts the key checkpoint, a new data key
  takes over at the next round.

## 6. Performance budget

Measured on the maintainer's laptop (arm64, Go 1.26.1) on 2026-10-21:

| Operation | Cost |
| --- | --- |
| DKLS23 3-of-3 signing, all parties and rounds, one process | 29.9 ms |
| FROST 3-of-3 signing, all parties and rounds | 3.0 ms |
| AES-256-GCM seal or open, 8 KB | ~1.1 µs |
| Durable 32 KB file commit (write and full sync) | 3.3 ms |

Envelope sealing is negligible. The durable commit per round is the only real
addition, about one DKLS23 round of compute, and small against a WAN round trip.
A remote KMS call per round would dominate; envelope encryption with a locally
held data key avoids it.

## 7. Increments and acceptance

Each increment ends with `make ci` green, an AUDIT.md entry stating what was
tested and what was only read, and the SECURITY.md, CHANGELOG.md, README.md and
CLAUDE.md updates the Documentation Duties require.

1. `envelope` package with tests: round trip, a mismatch matrix over every
   context field, header tampering, truncation, unknown version, a fuzz target
   for `Open`.
2. Bound wrappers for `SignerSetup` and `KeyShare`, demos rewired, upgrading
   note, AUDIT entry.
3. Encodings and wrappers for FROST `SignerState`, FROST round-1 state, dkls23
   round states and both packages' refresh private state.
4. Guard: in-memory mode, digest nonce markers, cold-signing documentation.
5. Session codecs for both protocols.
6. File-backed store, demos through the guard, cold-signing demo.

## 8. Decisions

- **File-backed store**: example only (decided 2026-10-21). Storage backends are
  the caller's, and a file store is no exception; the example shows the pattern
  and passes the conformance suite, nothing more.
- **`session` stays in this module** (proposed default): it is protocol-specific
  and tested against the real packages; a separate module would only add
  versioning friction. The alternative, splitting it out, would exist to keep an
  external crypto audit's surface smaller.
- **Encrypted unmarshal functions gain an expected-binding parameter** (proposed
  default): a compile error forces every caller onto the bound path. The
  alternative, new names beside the old functions, would leave the unbound path
  available.
- **DKLS23 pre-signing**: paper read (§3.3) and recorded as AUDIT.md FU-LOW-8
  on 2026-10-21. Pipelining is acceptable generally; pre-signing is an explicit
  opt-in under the paper's warning, with the single-use rule above enforced by
  the session stage record and a regression test.

## 9. Progress log

Kept current so another agent can resume. Each entry names the increment, the
commit, and what remains.

- 2026-10-21: design note written and reviewed; decisions in section 8 taken.
- 2026-10-21: DKLS23 §3.3 read; FU-LOW-8 and the presignature single-use test
  added.
- 2026-10-21: increment 1 (the `envelope` package) is handed to Codex. Claude's
  attempts to write it were twice halted by its output safety filter, so Codex
  implements it from section 1 of this note: `Encryptor` and the optional
  `ContextEncryptor`, `Context` with its canonical length-prefixed encoding,
  `Seal`, `Open` and `Peek` with the header check before decryption and the
  embedded check after it, typed errors naming the mismatched field, tests for
  the round trip, a mismatch matrix over every field, a spliced header,
  truncation, an unknown version, invalid contexts, and a fuzz target for
  `Open`; coverage at or above 90%; `envelope/README.md`; CLAUDE.md map and
  documents list; CHANGELOG "Added". Nothing of increment 1 exists in the tree.
