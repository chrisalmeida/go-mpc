# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

This release is a major version: it is not wire- or storage-compatible with
v0.x, and several APIs changed shape. See "Upgrading from v0.x" in the README.

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

[Unreleased]: https://github.com/chrisalmeida/go-mpc/compare/v0.2.0...develop
[0.2.0]: https://github.com/chrisalmeida/go-mpc/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/chrisalmeida/go-mpc/releases/tag/v0.1.0
