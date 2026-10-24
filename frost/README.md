# FROST — Threshold Schnorr on Ed25519

Implementation of **RFC 9591** ("Two-Round Threshold Schnorr Signatures with FROST") with the FROST(Ed25519, SHA-512) ciphersuite, plus the distributed key generation of the FROST paper (Komlo, Goldberg — SAC 2020), which the RFC leaves unspecified.

- RFC 9591: https://www.rfc-editor.org/rfc/rfc9591.html
- FROST paper: https://eprint.iacr.org/2020/852

---

## File overview

| File | Protocol component | Specification |
|---|---|---|
| `params.go` | Ciphersuite constants; `decodePoint` (RFC 8032 §5.1.3) and `deserializeElement` (RFC 9591 §6.1); scalar helpers | RFC 9591 §6.1 |
| `hash.go` | `H1`–`H5` domain-separated hashes; the DKG proof hash `H(i, Φ, φ_i0, R_i)` | RFC 9591 §6.1; FROST paper Fig. 1 |
| `keygen.go` | **KeyGen**: Feldman VSS with a Schnorr proof of knowledge of each constant term, verified before shares are sent | FROST paper Fig. 1 |
| `sign.go` | **Signing**: hedged `nonce_generate`, commitments, binding factors, group commitment, signature shares, **Aggregate** with share verification | RFC 9591 §4, §5 |
| `verify.go` | Cofactored signature verification; RFC 8032 compatibility | RFC 9591 §6.1 |
| `refresh.go` | Proactive share refresh with zero-constant Feldman polynomials | |
| `encoding.go` | Versioned JSON wire format for every message and persisted type | |
| `validation.go` | Validate local keys, participant membership, optional public metadata and refresh polynomial size before use | RFC 9591 §5 |
| `persistence.go` | Pluggable encrypted storage for `KeyShare` and `SignerState` | |
| `state_encoding.go` | Bound private signing and refresh checkpoints; strict versioned refresh JSON | Local persistence format |
| `session.go` | `SessionCodec.Signing` / `.Refresh` callbacks using encrypted authoritative state | Existing signing and refresh rounds |
| `errors.go` | Typed errors: `CheatingPartyError`, `InvalidInputError`, `CorruptStateError`, `BlacklistedPartyError` | |

---

## Protocol flow

| Phase | Calls | Messages |
|---|---|---|
| DKG round 1 | `DKGRound1` | broadcast Feldman commitments + proof of knowledge |
| DKG round 2 | `DKGRound2` (verifies every proof first) | one share per peer |
| DKG finalize | `DKGFinalize` | — |
| Sign round 1 | `SignRound1` | broadcast nonce commitment |
| Sign round 2 | `SignRound2` | signature share to the coordinator |
| Aggregate | `Aggregate` | final signature |

`Aggregate` verifies each share against the signer's verification share, names misbehaving signers in a `CheatingPartyError`, and verifies the final signature before returning it. Per RFC 9591 §5.4 and §7, that attribution assumes an authenticated channel and a coordinator that gives every signer the same commitment list.

Per RFC 9591 §5.1–5.2, each nonce pair is used once. Round 2 takes the
signer's write lock; copies of a state returned by `SignRound1` share one
consumption record protected by its own mutex, including across equivalent
signer wrappers. The state checks the matching key, participant set and epoch.
Treat exported fields as read-only and never reuse nonces for another session.
These local checks do not change the
signing equations, hash transcripts, message encoding or RFC test vectors.

Signing and refresh validate the configured local key before use, including
canonical scalar encoding and a matching verification share when provided.
Signing rejects participants outside `AllIDs`. Optional DKG metadata is checked
when present, but the original coefficient commitments cannot verify refreshed
secret shares. The current verification share is checked against the current
secret instead. See AUDIT.md FU-MED-10.

Refresh finalization records completed local contributions on the live signer
and rejects repeats. This local record is not serialized. Pending contribution
restoration is unchanged; durable replay protection, fresh authenticated peer
session routing and coordinated epoch activation remain caller responsibilities.
The module's `session` package provides the durable progress guard and the
refresh prepare/activate gate over a caller-supplied transactional store;
`store_test.go` drives a full signing session through it.

---

## Conformance

- `vectors_test.go` runs the RFC 9591 Appendix E.1 vectors through the implementation and checks nonce derivation, commitments, binding-factor inputs and factors, both signature shares, and the final 64-byte signature exactly.
- Received protocol elements are parsed with `deserializeElement`: canonical encoding, not the identity, in the prime-order subgroup. Public signature verification uses RFC 8032 decoding and the cofactored equation required by RFC 9591 §6.1, including acceptance of small-order components as tested by `TestVerifyCofactoredEquation`.
- Honestly produced signatures are accepted by `crypto/ed25519.Verify`.

[SECURITY.md](../SECURITY.md#evidence-and-test-coverage) identifies the tests
for these behaviors and the limits of timing and memory-erasure assurance.

---

## Dependencies

- `filippo.io/edwards25519` — constant-time Ed25519 scalar and point arithmetic
- Standard library: `crypto/rand`, `crypto/sha256`, `crypto/sha512`, `crypto/subtle`

## Cold signing and encrypted imports

`SessionCodec{Encryptor: enc}.Signing(...)` and `.Refresh(...)` return callbacks
for `session.Advance`. Initialize the store with the bound encrypted key checkpoint,
then pass the current authoritative version, operation, participants and round.
`Advance` returns encrypted outbound bytes only after commit; `session.Output` recovers exact
cached ciphertext. Use `codec.OpenOutput` before decoding and transport. Refresh
round-2 messages contain secret shares; `OpenRefreshRound2` parses them after
commit and each share needs confidential delivery. Each callback decodes fresh key and round objects. Refresh prepares
a candidate before caller-coordinated `Activate`.

For devices that shut down, use the default `session.Resumable` mode. For online
operations use `session.Memory.Advance` and retain that Memory object between
rounds; losing it requires an explicit abort. Encryption and serialization alone
do not stop replay of a backup. Never roll back the authoritative progress store.
Memory clears superseded checkpoint buffers after confirmed commits and retains
state across uncertain outcomes; see [session](../session/README.md) and FU-LOW-10.

Encrypted imports now require an expected `KeyBinding` from trusted application
records. `SetupEncryptor` aliases `envelope.Encryptor` and requires authenticated
encryption. The root README gives the explicit legacy decrypt/validate/reseal
migration; existing plaintext and protocol wire formats are unchanged.

`TestEncryptedSessionCodecSigningRefreshAndRestart` checks encrypted signing,
refresh and post-refresh signing, lost commit acknowledgement, concurrent and
sequential reuse, and independently verified signatures. New private JSON types
have receiver-preservation error tables and fuzz targets. The example module also
runs real processes against the file store; see AUDIT.md FU-MED-14.

Run `go -C example/cold-frost run . demo DIRECTORY` from the repository root
with `MPC_WRAPPING_KEY` set to a 32-byte hex demo key and an empty directory.
`init`, `commit`, `request`, `sign` and `aggregate` also run individually; `--help`
and the [root README](../README.md) show the file flow. The request builder takes
commitments in participant order. `TestColdSigningSeparateProcessesAndCachedOutput`
checks the commands across restarts, relocation, failed file delivery and cached
retry, then verifies the signature with `crypto/ed25519`. The example node's
`SaveSignerState` / `LoadSignerState` retain epochs and blacklists;
`TestSignerSnapshotRetainsRefreshedEpochAndBlacklist` checks a real refresh,
restoration, blacklist rejection and independently verified signing. Existing
bare-key helpers retain their epoch-zero behavior. See AUDIT.md FU-LOW-9.

`MarshalSignerEncrypted` retains the key, epoch and blacklist. Bare `KeyShare`
encryption is epoch zero. `MarshalRound1Encrypted` seals unused RFC 9591 nonces;
restoration gets a fresh shared local use record, while cross-restoration one-use
comes from authoritative session progress. Raw JSON or reopening a blob twice
cannot provide that guarantee by itself.
