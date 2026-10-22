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
