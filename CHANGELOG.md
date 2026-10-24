# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Complete command-line cold-signing examples for DKLS23 and FROST, with manual
  request builders, `--help`, runnable README commands and both demos in CI.
  Process tests cover device relocation, failed file delivery, cached retries,
  wrong-key rejection and independent signature verification. Add FROST signer
  snapshot helpers that retain refreshed epochs and blacklists; preserve the
  legacy bare-key helpers. (AUDIT.md FU-LOW-9)
- **Portable cold signing and refresh for both protocols.** Add bound private
  signing and refresh codecs, trusted key bindings, stateless `SessionCodec`
  callbacks, encrypted outbound caches and explicit post-commit `OpenOutput`.
  Confidential refresh shares also have `OpenRefreshRound2`. Add optional
  `session.Memory` for online operations; resumable remains the zero mode.
  Add the example Linux/macOS file store with conformance and process-crash
  tests, both demos through the guard, FROST file-transfer commands and real
  process-restart signing/refresh tests. No protocol transcript or vector changes.
  (FU-MED-14)
- **`envelope` package.** Add `Seal`, `Open`, `Peek`, canonical context encoding,
  typed errors and caller-supplied authenticated encryption with optional header
  associated data. Check trusted expected binding before decryption and embedded
  context before private payload release. (FU-MED-13)
- **`session` package: transactional progress guard** for DKLS23 and FROST
  signing and refresh over a caller-supplied `session.Store`. `Advance` commits
  at most one result per operation and round, saving the key checkpoint,
  private round checkpoint, nonce marker, cached output and blacklist changes
  atomically before returning bytes to send; `Output` replays committed bytes
  after a lost acknowledgement; a revision check rejects stale backups;
  refresh is prepared by its final round and promoted by `Activate`. After
  rollback, a later explicit call can recompute the round from fresh checkpoints.
  `session/storetest` provides the `Store` conformance suite and an in-memory
  fault-injecting model. No protocol, wire format or persisted format changes;
  the repository ships no production backend. (AUDIT.md FU-MED-6)

### Changed

- **Breaking: encrypted imports require `KeyBinding`.** Both
  `UnmarshalEncrypted` functions now take the trusted expected key/party/epoch.
  `SetupEncryptor` aliases `envelope.Encryptor`; authenticated implementations
  retain their methods. Legacy unbound ciphertext requires explicit
  decrypt/validate/reseal migration. Existing plaintext and protocol formats
  remain unchanged; legitimate pending state and authoritative progress can be
  retained. FROST signer envelopes retain epoch/blacklist; bare keys are epoch zero.
- New nonce reservations are SHA-256 digests; existing raw reservations remain
  checked. Store adapters must retain operation mode and accept 32-byte markers.
- Example wrapping keys come from the environment, with no colocated `enc.key`.
  Each blob gets a wrapped fresh data key and authenticated key ID. Legacy demo
  directories fail explicitly; CI uses disposable fixtures and never overwrites
  a maintainer's shares directory.

### Security

- **session: verify mode persistence and clear superseded memory checkpoints.**
  The store conformance suite checks both mode values across reopening and
  rejects an adapter that drops `Record.Mode`. `Memory.Advance` clears older
  checkpoint buffers after confirmed commits while retaining needed state on
  uncertain outcomes and preserving other operations/scopes. Mode defaults,
  stored formats and protocol transcripts are unchanged. (FU-MED-16, FU-LOW-10)
- Fix example file-store lookup and locking across processes with different Gob
  type histories. Retain existing partition filenames and pending progress;
  reject duplicate scope files before running a transaction. Add a failing-first
  restart regression and concurrent writers with different encoding histories.
  (AUDIT.md FU-MED-15)
- **dkls23: document pipelining and pre-signing per DKLS23 §3.3.** Rounds 1
  and 2 take no message and round 3 does, which is the paper's pre-signing
  point. Pipelining is acceptable generally; pre-signing is an explicit opt-in
  under the paper's warning, and a presignature completes exactly one message,
  enforced by the session stage record and covered by a regression test. No
  code change. (AUDIT.md FU-LOW-8)
- **session: strengthen rollback conformance and narrow execution claims.**
  `storetest.Run` now checks that errors and panics preserve previously
  committed key/session records, cached outputs and nonce reservations while
  discarding tentative writes. Regression tests reject adapters that erase
  progress during rollback. Documents state at most one committed result per
  round and cover recomputation after rollback; passing the conformance suite
  alone does not establish the complete storage contract. (FU-MED-11, FU-MED-12)
- **both: validate local signing and refresh material before use.** Reject
  invalid group configuration, malformed key material and unconfigured signing
  participants before returning output. DKLS23 checks all selected peers' base
  OT/FZero material, locally recomputable private round-state equations and
  retained peer-map entries. FROST checks canonical shares and the matching
  verification share when present. Refresh rejects missing or incorrectly
  sized local polynomials. Valid restoration, partial DKLS23 pairwise setup
  and refreshed FROST shares remain supported. Persisted formats and protocol
  transcripts are unchanged; strict raw decoding, state origin binding and
  durable recovery remain separate open work. (AUDIT.md FU-MED-10)
- **frost: serialize nonce consumption** per RFC 9591 §5.1–5.2. Concurrent
  round-2 calls and copies of a returned round-1 state share one consumption
  record protected by its own mutex, including across equivalent signer
  wrappers. States check the matching key, participant set and epoch.
  Regression tests verify one successful call and a valid signature.
  (AUDIT.md FU-HIGH-2)
- **dkls23: use constant-time secp256k1 point operations and encoding** via
  `github.com/bytemare/secp256k1` v0.5.0, replacing secret uses of btcec's
  `NonConst` operations. Scalar arithmetic and independent ECDSA verification
  continue to use btcec. No protocol equation, hash input or message changes.
  This backend and its integration still require independent audit.
  (FU-HIGH-3)
- **dkls23: reduce FZero PRF outputs in constant time.** The former
  `reduce64Public` passed secret outputs to `math/big`. The replacement
  computes the identical 512-bit integer reduction using `ModNScalar` and the
  existing gadget vector. Differential tests pin the reduction and PRF input.
  (FU-MED-5)
- **both: reject duplicate refresh finalization on live signer objects.**
  Completed local seed contributions are recorded after successful updates
  under the signer's write lock. Pending contributions retain their existing
  restoration behavior. The local record is not serialized; durable replay
  protection and authenticated session routing remain caller responsibilities.
  (FU-MED-7)
- **both: preserve live state after rejected imports.** Unsupported versions
  and malformed fields no longer partially replace signer state, invalidate
  active signing sessions or erase pending refresh. DKLS23 private round-state
  decoding also publishes replacements only after validation. Tests complete
  the original operations and independently verify their signatures. (FU-MED-8)

### Changed

- FROST round 2 takes the signer's write lock. Distinct sessions can interleave
  between rounds, but their round-2 calls on one signer execute serially.
- Map security claims to named tests, distinguish inspected source from
  measured timing and erasure, and clarify strict FROST protocol decoding
  versus cofactored signature verification. Repair version-masked error
  tests, add missing decoder fuzz targets and test sequential/concurrent
  DKLS23 round replay with independent signature verification. (FU-LOW-7)

### Fixed

- Preserve receivers on rejection in every custom JSON decoder, extending
  transactional decoding to the remaining key, message and ephemeral state
  types with populated-receiver regression tests. Successful decoding
  behavior and wire formats are retained. (FU-MED-9)

## [0.3.0] - 2026-10-21

This release is a breaking change: it is not wire- or storage-compatible with
v0.2.x, and several APIs changed shape. See "Upgrading from v0.2.x" in the
README. The library stays at v0.x until an independent audit; v1.0.0 will
mark the point where the public API is frozen.

### Security

- **dkls23: fixed a key-recovery flaw (critical).** The OT-extension batch and
  the VOLE correlation derived from it were produced once at setup and reused
  by every signing session, which let any co-signer recover the master private
  key from two signatures. Only the base-OT seeds are persistent now; every
  signing session runs a fresh OT-extension batch and VOLE, as DKLS23
  Functionality 5.1 and §8.2 require. (AUDIT.md FU-CRIT-1)
- **dkls23: the OT extension now has a consistency check (high).** The plain
  IKNP extension is replaced by KOS15 with the one-message Fiat-Shamir check of
  DKLS23 §5.1; an inconsistent batch is detected and its sender blacklisted.
  (FU-HIGH-1)
- **dkls23: key generation is commit-then-reveal** per Protocol 7.1, closing a
  public-key bias by a rushing party, and the Feldman commitment count is
  enforced. (FU-MED-1, FU-MED-2)
- **frost: the DKG carries a proof of knowledge** of each party's constant
  term (FROST paper Figure 1), verified before any share is sent, against
  rogue-key attacks. (FU-MED-3)
- **frost: received elements are decoded per RFC 9591 §6.1** (canonical,
  non-identity, prime-order subgroup), and the Appendix E.1 test vectors are
  reproduced exactly by the test suite. (FU-MED-4)
- **dkls23: the base OT is now Masny-Rindal** (MR19 Figure 8, Diffie-Hellman
  instantiation) as DKLS23 §8.1 specifies. (FU-LOW-4)
- **dkls23: session-id freshness is enforced** (Protocol 3.6 step 4).
  `SignerSetup.SessionIDs` records each session's progress; a reused id, a
  replayed `Round1State`, or a second round 3 is rejected with
  `SessionIDReusedError`. The record is persisted and cleared by refresh.
  (FU-LOW-6)

### Changed (breaking)

- Persisted `SignerSetup` (dkls23) and `KeyShare` / `SignerState` (frost)
  carry a `"version"` field and reject documents without it. Key material
  saved by v0.x must be regenerated.
- dkls23 `DKGRound1` returns a `*DKGPrivateState`; `DKGRound2` requires every
  other party's round 1 output; Feldman commitments are released in round 2.
- dkls23 `SignerSetup` stores `AliceBaseOT` / `BobBaseOT` seeds instead of
  VOLE state; `SignSetupPairwise`, `SignCounter`, and the former OT-extension
  and base-OT setup functions are removed.
- dkls23 base OT: the receiver speaks first (`BaseOTReceiverRound1` →
  `BaseOTSenderRound2` → `BaseOTReceiverFinalize`); the setup message types
  changed accordingly.
- dkls23 `Round1Msg` carries the session's OT-extension batch for its
  recipient.
- dkls23 `SignCombine` ignores an entry under the caller's own party ID.
- dkls23 `SignRound1` takes the setup's write lock (it records the session),
  so rounds of concurrent sessions execute one at a time per `SignerSetup`;
  `SignerSetup` gains `SessionIDs` and its JSON gains `session_ids`.
- frost `DKGPartyConfig` gains `Context`; `DKGRound1Output` gains `ProofR` and
  `ProofMu`; `DKGRound2` takes all parties' round 1 outputs.
- frost rejects non-canonical, identity, and non-prime-order points wherever
  an element is received.

### Added

- dkls23: `gf128.go` constant-time GF(2^128) arithmetic; regression test
  `TestSignSessionsUseFreshVOLE`; direct tests of base-OT seed correlation
  across refresh.
- frost: `vectors_test.go` (RFC 9591 Appendix E.1); `element_test.go`.
- CI: gofmt check, `go mod tidy` check, example runs, fuzz smoke pass,
  govulncheck; `make fmt`, `make fuzz`, `make vuln`, `make examples`.
- A follow-up review section in AUDIT.md documenting every finding above.

### Changed

- Minimum Go version is 1.26 (required by `golang.org/x/crypto` v0.58.0);
  `go.mod` pins `toolchain go1.26.1`.
- Dependencies refreshed: `btcec` v2.5.0, `decred/secp256k1` v4.4.1,
  `golang.org/x/crypto` v0.58.0, `testify` v1.12.1.
- frost: `DKGPartyConfig.Context` must be non-empty; `DKGRound1`,
  `DKGRound2` and `DKGFinalize` reject an empty context with
  `InvalidInputError`, since an empty Φ gives the proofs of knowledge no
  replay protection.
- CI and `make test-race` allow 600 seconds per package for the
  race-detected suite.

### Fixed

- dkls23 demo now persists refreshed shares so a reload uses the current
  epoch.
- Documentation no longer claims non-canonical point rejection in frost or
  rollback protection from `SignCounter` in dkls23; both were inaccurate.

## [0.2.0] - 2026-04-03

### Added

- `frost` package: FROST threshold Schnorr over Ed25519 per RFC 9591, with
  distributed key generation, signing, aggregation, verification, and
  proactive key refresh.
- `example/frost` demo; `example/shared` AES-256-GCM encryptor shared by both
  demos.

### Changed

- The DKLS23 demo moved to `example/dkls23`.
- Removed the mutable `randRead` test hook from frost.

## [0.1.0] - 2026-03-27

### Added

- `dkls23` package: DKLS23 threshold ECDSA over secp256k1 with distributed
  key generation, 3-round signing, proactive key refresh, and encrypted
  persistence.

[Unreleased]: https://github.com/chrisalmeida/go-mpc/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/chrisalmeida/go-mpc/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/chrisalmeida/go-mpc/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/chrisalmeida/go-mpc/releases/tag/v0.1.0
