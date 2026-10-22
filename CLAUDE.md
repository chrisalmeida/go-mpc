# CLAUDE.md

Guidance for anyone (human or agent) changing this repository. Read it fully before touching `dkls23/` or `frost/`.

## Project Overview

Threshold signing library in Go. Two protocols, implemented strictly from their published specifications:

- **DKLS23** — Threshold ECDSA over secp256k1 ([ePrint 2023/765](https://eprint.iacr.org/2023/765), IEEE S&P 2024).
- **FROST** — Threshold Schnorr / Ed25519 ([RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html), FROST(Ed25519, SHA-512)), with the DKG of the [FROST paper](https://eprint.iacr.org/2020/852).

- **Module**: `github.com/chrisalmeida/go-mpc`
- **Go**: `go 1.26.0` minimum (required by `golang.org/x/crypto`), `toolchain go1.26.1` pinned in `go.mod` (CI reads it via `go-version-file`)
- **Scope**: cryptography only. Callers supply transport, authentication, broadcast, session ids, and storage. No resharing (changing t or n), no key derivation.

## Repository Map

- `dkls23/` — DKLS23 package. Every file is security-critical.
  - `params.go` — security parameters (`Kappa`, `LambdaC`, `LambdaS`, `Xi`, `XiExt`, `Rho`, `Ell`), all domain-separation tags, gadget vector, `scalarInverse`, `reduce64` (constant-time 64-byte reduction mod q), package doc
  - `curve.go` — the only place secp256k1 point arithmetic happens: `curvePoint` (the `bytemare/secp256k1` fixed ladder and complete addition), `scalarMulG`, `scalarMul`, `pointToCompressed`, `compressedToPoint`, `selectPoint`
  - `dkg.go` — commit-then-reveal Feldman VSS key generation (Protocol 7.1): `DKGRound1` → `DKGRound2` → `DKGFinalize`, `DKGPrivateState`
  - `ot.go` — Masny-Rindal endemic base OT (MR19 Figure 8, DH instantiation; §8.1): `BaseOTReceiverRound1` → `BaseOTSenderRound2` → `BaseOTReceiverFinalize`; `sampleScalar`, `hashToCurve`
  - `ot_extension.go` — KOS15 OT extension with the one-message Fiat-Shamir consistency check (§5.1): `OTExtReceive` (Bob) / `OTExtSend` (Alice); one fresh batch per signing session
  - `gf128.go` — constant-time GF(2^128) multiply for the consistency check
  - `vole.go` — random VOLE (Protocol 5.2): `VOLEBobSample`, `VOLEAliceSetup`, `VOLEAliceMultiply`, `VOLEBobReceive`
  - `commitment.go` — FCom (`Commit`/`Open`) and FZero (`FZeroSetupRound1`, `FZeroSetupFinalize`, `FZeroSample`)
  - `sign.go` — Protocol 3.6: `SignerSetup`, `SignRound1` (commit R_i, run Bob's OT-extension batch per counterparty), `SignRound2` (verify batch, derive VOLE, multiply, decommit), `SignRound3` (checks 1-3, fragments), `ComputeRx`, `SignCombine`
  - `refresh.go` — KMOS21 proactive refresh of shares, base-OT seeds and FZero seeds: `RefreshRound1` → `RefreshRound2` → `RefreshFinalize`
  - `setup_messages.go` — wire types for the one-time pairwise setup (FZero messages; base-OT messages live in `ot.go`)
  - `encoding.go` — JSON marshaling for every type; `SetupWireVersion`
  - `persistence.go` — `SetupEncryptor` interface, `MarshalEncrypted`/`UnmarshalEncrypted`
  - `errors.go` — `CheatingPartyError`, `InvalidInputError`, `CorruptStateError`, `BlacklistedPartyError`
- `frost/` — FROST package. Every file is security-critical.
  - `params.go` — ciphersuite constants, `decodePoint` (RFC 8032 §5.1.3), `deserializeElement` (RFC 9591 §6.1), scalar helpers, package doc
  - `hash.go` — `H1`–`H5` (RFC 9591 §6.1) and `hashDKGProof` (the FROST paper's H for the DKG proof)
  - `keygen.go` — FROST paper Figure 1 KeyGen with proof of knowledge: `DKGRound1` → `DKGRound2` (verifies every proof) → `DKGFinalize`
  - `sign.go` — RFC 9591 §4–5: `SignerState`, `SignRound1`, `SignRound2`, `Aggregate` (share verification, final verification)
  - `verify.go` — cofactored verification (`Verify`, `VerifyBytes`)
  - `refresh.go` — proactive refresh with zero-constant polynomials
  - `encoding.go` — JSON marshaling; `WireFormatVersion`
  - `persistence.go`, `errors.go` — as in dkls23
- `example/` — separate module (`go.mod` with `replace github.com/chrisalmeida/go-mpc => ../`), not part of `go test ./...`
  - `shared/` — AES-256-GCM `SetupEncryptor` used by both demos
  - `dkls23/` — 3-of-3 demo: DKG → base OT + FZero → persist → sign → refresh → persist → sign; `node/` wraps the package per party
  - `frost/` — 2-of-3 demo with every signer subset, persistence and refresh
  - Each demo writes `shares/` (gitignored); delete it to start from a fresh DKG
- Documents: `README.md` (user-facing, includes "Upgrading from v0.x"), `dkls23/README.md` and `frost/README.md` (per-package file maps and protocol flow), `SECURITY.md` (threat model, timing design and evidence, limitations, disclosure), `AUDIT.md` (findings with IDs; the 2026-10-16 follow-up section and the 2026-10-21 hardening addendum supersede the original text where they disagree), `CHANGELOG.md` (Keep a Changelog), `CONTRIBUTING.md`, `AGENTS.md` (a pointer to this file for agents that read that name instead; keep it a pointer, not a copy)

## Development Workflow

```bash
make test          # go test ./...
make test-race     # go test -race (what CI runs)
make lint          # gofmt + go vet + staticcheck (pinned v0.7.0)
make cover         # coverage summary
make bench         # benchmarks
make fuzz          # every fuzz target, 5s each
make vuln          # govulncheck (pinned v1.9.0)
make examples      # vet and run both demos
make ci            # everything CI runs; must be green before any PR or commit to develop/main
```

- **Before finishing a change**: `make ci`. It takes a few minutes locally (race tests, both demos, fuzz smoke, govulncheck). Do not skip it for "small" changes; the demos and fuzz targets have caught real regressions.
- **Tool versions are pinned** (Go toolchain in `go.mod`, staticcheck and govulncheck in both `Makefile` and `.github/workflows/ci.yml`). Bump them deliberately and in both places; `go mod tidy` must leave `go.mod`/`go.sum` unchanged (CI checks this).
- **Branches**: work on `develop` (or a feature branch), open a PR into `main`. CI runs on PRs and on pushes to `main`; pushes to `develop` alone do not trigger it.
- **Commits**: imperative summary line, a body that says what changed and why, and the attribution trailer the maintainer uses. Never commit `shares/` directories, keys, or fuzz corpora unless a corpus entry documents a fixed bug.
- **Dependencies**: add one only if the cryptography requires it. Current direct dependencies: `btcec` (secp256k1 constant-time scalars; public ECDSA verification), `bytemare/secp256k1` (constant-time point arithmetic and SEC1 encoding; pinned, no transitive dependencies), `filippo.io/edwards25519`, `golang.org/x/crypto` (SHAKE-256), `testify` (tests only). Before adding or upgrading a dependency that touches secret data, read its source for the timing behaviour you rely on; its README is a claim, not evidence (rule 11).

## Conventions

- Error messages: `"dkls23 FunctionName: description"` / `"frost FunctionName: description"`; wrap underlying errors with `%w`. Use the typed errors for anything a caller must act on (cheating, bad input, corrupt state, blacklisted party).
- Protocol functions are named by role and round (`SignRound1`, `BaseOTSenderRound2`, `RefreshFinalize`); per-counterparty outputs are `map[int]*Msg` keyed by party ID; a function's inputs from peers are `map[int]*Msg` keyed by sender.
- Every exported type and protocol function has a GoDoc comment naming the protocol, figure, or section it implements. Where a spec leaves a detail open, the GoDoc says what was chosen and why.
- `gofmt`, `go vet`, `staticcheck` clean; no `//nolint`, no TODOs in security-critical code (fix it or file a finding in AUDIT.md).
- No logging and no printing of secret material anywhere in the packages; the demos print only public values.
- Public API changes, persisted-format changes, and security fixes are breaking or notable changes: record them (see Documentation Duties).

## Security Rules for Protocol Changes

These rules exist because the 2026-10-16 review found that earlier code had drifted from the specifications in exploitable ways (AUDIT.md FU-CRIT-1 onward), and because the 2026-10-21 review then found five properties that function names, comments and SECURITY.md asserted but the code did not have (FU-HIGH-2, FU-HIGH-3, FU-MED-5, FU-MED-7, FU-MED-8). They apply to every change and every review under `dkls23/` and `frost/`.

1. **Implement the cited specification; never invent.** dkls23 follows the DKLS23 paper and the papers it delegates to: KOS15 ([ePrint 2015/546](https://eprint.iacr.org/2015/546)) for the OT extension, Masny-Rindal ([ePrint 2019/706](https://eprint.iacr.org/2019/706)) for the base OT, KMOS21 ([ePrint 2019/1328](https://eprint.iacr.org/2019/1328)) for refresh. frost follows RFC 9591 and, for the DKG the RFC does not specify, the FROST paper. If the spec does not say it, do not add it; if a detail is open (an encoding, a domain tag, a hash input order), choose the simplest unambiguous option and document it in the GoDoc and in AUDIT.md.
2. **Only one-time setup material is persistent in dkls23.** `SignerSetup` stores base-OT seeds (`AliceBaseOT`, `BobBaseOT`) and `FZeroSeeds`. OT-extension batches and VOLE correlations belong to one signing session and must never be stored, cached, or reused: reuse reveals nonce differences and recovers the key.
3. **Every signing session needs a fresh session id** (DKLS23 Protocol 3.6 step 4) and every FROST DKG a fresh `Context`. dkls23 enforces freshness per setup and epoch through `SignerSetup.SessionIDs` (each round of a session runs exactly once; reuse is `SessionIDReusedError`; `RefreshFinalize` clears the record because the new seeds re-key everything an id feeds into). Keep that enforcement when changing the signing rounds, and keep the caller-side requirement documented.
4. **Validate everything received before use.** Lengths, canonical encodings, points on the curve, and for frost protocol elements the full RFC 9591 §6.1 rules through `deserializeElement` (non-identity, prime-order subgroup). Parse protocol elements with the strict helper, never with the raw library decoder. Public signature verification follows the separate RFC 8032 decoding and cofactored equation required by RFC 9591 §6.1; retain that distinction (see `Verify` and `TestVerifyCofactoredEquation`).
5. **Attribute misbehaviour correctly.** Report with `CheatingPartyError.PartyIDs`; blacklist only where the specification's channel assumptions make the attribution sound (authenticated point-to-point channels; for FROST a coordinator that does not equivocate). Protocol-level inconsistency that cannot be pinned on a party is `CorruptStateError`, not a blacklist.
6. **No secret-dependent control flow or memory access.** Secret bits select with masks or `subtle.ConstantTimeCopy`; secret scalars use the constant-time scalar types; secp256k1 point multiplication and encoding go through `curve.go` only, never btcec's `NonConst` functions, which btcec itself documents as variable-time; `math/big` appears only in tests; comparisons of secret-derived values use `subtle.ConstantTimeCompare`; ephemeral secrets (coefficients, nonces, OT scalars, Lagrange coefficients, PRG state) are zeroized when no longer needed.
7. **Constants are part of the protocol.** Domain-separation tags live only in each package's `params.go`; parameter values (`Xi`, `XiExt`, `LambdaC`, hash input orders, serialization orders) change interoperability and the test vectors. Changing any of them is a breaking protocol change and needs a spec citation.
8. **Versioned wire formats.** Any change to a persisted or exchanged type that has shipped in a tagged release bumps `SetupWireVersion` (dkls23) or `WireFormatVersion` (frost); every type keeps strict validation in `UnmarshalJSON` and a rejection test for old or missing versions. Changes before a format's first release may keep the version number.
9. **Tests prove behaviour, not the absence of errors** (see Testing). `frost/vectors_test.go` (RFC 9591 Appendix E.1) and `dkls23` `TestSignSessionsUseFreshVOLE` must keep passing unchanged; if a change makes either fail, the change is wrong.
10. **Never weaken a check to make a test pass.** When a test and the code disagree, decide from the specification which one is wrong, and say so in the commit message.
11. **Verify every claim; inherit none.** A function name, a comment, a GoDoc sentence, a SECURITY.md claim, an AUDIT.md resolution, or a dependency's README is a hypothesis, not evidence. The 2026-10-21 review found `reduce64Public` applied to secret FZero output, a dependency table that said "constant-time point multiplication" above code calling btcec's `ScalarMultNonConst`, and "epoch prevents replay" describing a counter that nothing checked; the earlier review had read those claims and repeated them. Before relying on a property, or writing it into any document:
    - find the test that would fail if the property were false, or write it;
    - for every library primitive applied to secret data, read that library's own documentation and source for its timing behaviour and cite it in the GoDoc; `grep -rn 'NonConst(\|"math/big"' --include='*.go' dkls23 frost | grep -v _test.go` must print nothing (it matches calls and imports, not comments);
    - for every one-use or single-application guard (`consumed`, `SessionIDs`, refresh contributions), call it twice sequentially and concurrently under `-race` in a test and assert exactly one success;
    - for every `UnmarshalJSON`, assert the receiver is unchanged after a rejected input.

    A review that only confirms the documents agree with the code has reviewed nothing. In AUDIT.md, say for each finding what was tested and what was only read, and treat any claim without a falsifying test as a Known Limitation, not a guarantee.

### Security-sensitive areas by package

- **dkls23**: the curve backend adapter and `selectPoint` in `curve.go`; `reduce64` on FZero output; DKG commitment opening and commitment-count check; base-OT message validation and identity rejection; OT-extension consistency check and pad handling; VOLE Fiat-Shamir proof; R-commitment decommitment and checks 1-3; final signature verification in `SignCombine`; refresh commitment opening and seed re-randomization; encryption key handling in persistence.
- **frost**: DKG proof-of-knowledge verification and Feldman checks; `deserializeElement` on every received element; hedged nonce generation and the `consumed` guard plus shared `nonceUse` record against nonce reuse (round 2 holds the signer's write lock); binding-factor and commitment-list encoding; share verification in `Aggregate`; cofactored verification; refresh commitment and count checks; encryption key handling.

## Testing

### What a test must do

- Correctness of the honest path, asserting on protocol values (seeds match across parties, signatures verify with an independent verifier, vectors match exactly), not merely `NoError`.
- For every field a party receives: a tampering or malformed-input test showing the value is rejected, the right party is named (`CheatingPartyError.PartyIDs` via `errors.As`), and, where the protocol says so, blacklisted; and a test that honest parties are unaffected.
- Where a specification publishes vectors, a vector test with the hex copied exactly from the source document.
- Regression tests for every security finding, named after the property (`TestSignSessionsUseFreshVOLE`, `TestRefreshBaseOTSeedsStayCorrelated`).
- Names describe the behaviour under test (`TestDKGRejectsPolynomialChangedAfterCommitment`, `TestOTExtensionMaliciousReceiverInconsistentRow`); a name must not claim more than the assertions check. Grab-bag tests get split.
- Every wire type has a `FuzzUnmarshal<Type>` target and a table of unmarshal error cases; every `UnmarshalJSON` must fail cleanly on bad input: no panic, and the rejection test asserts the receiver re-marshals byte-identical to its state before the call, not merely that an error is returned.
- Every one-use or single-application guard has a sequential second-call test and a concurrent test under `-race`, each asserting exactly one success and that the resulting signature or state still verifies independently.
- Every property stated in SECURITY.md or a GoDoc comment is backed by a test that would fail if it were false, and the test name or AUDIT.md entry says which claim it backs. A claim with no such test moves to Known Limitations (rule 11).
- Coverage stays at 90%+ per package; everything runs under `-race`.

### dkls23 fixtures (`helpers_test.go`, `sign_test.go`, `dkg_test.go`)

- `fullSetup(t)` — cached 3-of-3 `SignerSetup` per party (DKG + base OTs + FZero, built once with `sync.Once`, deep-copied through JSON). Use it for any standard 3-of-3 test.
- `setupSigners(t, ids, threshold)` / `buildSetups` — fresh setups for other configurations (2-of-3, 2-of-2); pairwise setup runs in parallel goroutines.
- `runBaseOT()` — one complete base OT, returning `BaseOTReceiverSeeds` and `BaseOTSenderSeeds`; `runVOLEPairwise()` / `runVOLESession(alice, bob, sid)` — one OT-extension batch plus VOLE sampling over fresh or given seeds.
- `runRound1`/`runRound2`/`runRound3`/`runSession` — return a `signingSession` whose messages (`r1Msgs`, `r2Msgs`, `r3Frags`) can be tampered with between rounds; `runSigning` runs a full session plus `SignCombine`; `verifyECDSA` checks the result with btcec.
- `runDKGRounds` / `runDKG` — DKG rounds with all private states exposed for tampering tests.
- `roundTrip(t, name, v)` — marshal/unmarshal/marshal JSON equality.

### frost fixtures (`helpers_test.go`, `keygen_test.go`, `refresh_test.go`, `element_test.go`)

- `fullSetup(t)` — cached 3-of-3 `KeyShare` per party; `buildDKG(allIDs, threshold)` for other configurations.
- `fullSign(t, keyShares, signers, msg)` — round 1 → round 2 → `Aggregate` with share verification; `fullSignWithStates` for existing `SignerState`s; `makeSignerStates`.
- `runDKGRound1` / `runDKGRound2` — a `dkgSession` with configs, coefficients, and messages exposed; `requireCheating(t, err, ids...)` asserts a `CheatingPartyError` naming exactly those parties; `requireRound2AndFinalizeReject`.
- `invalidElements(t)` — the catalogue of encodings `deserializeElement` must reject (identity, small order, mixed order, non-canonical, wrong length); reuse it when a new place parses an element.
- `vectorSigners` and the `vec*` constants — RFC 9591 Appendix E.1 values; never edit them to make a test pass.

### Performance

CI runners are 3-5× slower than a laptop. Every test that does crypto work (base OT, OT extension, VOLE, signing, refresh, DKG with more than a couple of parties) uses `t.Parallel()`; this is safe because fixtures return independent copies. Prefer the cached fixtures over fresh setups, never share mutable state between parallel tests, and keep per-test work proportionate (a few sessions, not hundreds).

## Persistence and Wire Format

- JSON with hex-encoded byte fields; big arrays use base64 (`encodeVOLESlice`). Maps keyed by party ID use string keys.
- `SignerSetup` JSON carries `"version": SetupWireVersion`; `KeyShare` and `SignerState` carry `"version": WireFormatVersion`. Unmarshaling rejects missing or different versions, so old key material is never misread.
- `SetupEncryptor` is the caller's: the packages never choose a cipher or hold an encryption key. The demos' AES-256-GCM encryptor is an example, not a recommendation for key management.
- Marshaled `SignerSetup` / `KeyShare` contain plaintext secret shares and seeds. Treat the output of `MarshalSetup` / `MarshalKeyShare` as secret; only the `*Encrypted` variants are safe to write to disk.

## Documentation Duties

Code changes are not done until the documents match:

- **AUDIT.md** — every security-relevant finding gets an ID (`FU-<SEV>-<n>` in the follow-up section), with file, severity, category, failure scenario, and resolution. Do not rewrite the original review's text; it is history, and the note at the end of the follow-up section says it is superseded where they disagree. Each entry says what was tested and what was only read.
- **SECURITY.md** — every claim (constant-time properties, what is validated, what is persisted, limitations) must remain true after the change. If a claim stops being true, change the claim. Every claim names, there or in AUDIT.md, the test or cited library guarantee that backs it; never add or keep a claim on the strength of a name, comment, or README.
- **CHANGELOG.md** — an entry under `Unreleased` for every notable change; breaking changes and security fixes are labelled as such.
- **README.md** — the feature descriptions and quick starts reflect the current API; breaking changes are added to the upgrading section.
- **Package READMEs** — the file overview and protocol-flow tables name the current files and functions.
- **GoDoc** — spec citations stay accurate when code moves.
- **CLAUDE.md** — the repository map, dependency list, and security rules name the current files, functions, and dependencies. Stale guidance teaches the next reader a falsehood, which is exactly what rule 11 exists to prevent.

## CI

`.github/workflows/ci.yml` runs on pull requests and on pushes to `main`: gofmt check → `go mod tidy` check → `go vet` → staticcheck → `go test -race` with coverage → coverage summary → vet and run both example programs → 5-second fuzz pass over every fuzz target → govulncheck. `make ci` reproduces it locally and must pass before pushing.

## Release Checklist

1. `make ci` green on the release commit, on `main`.
2. `CHANGELOG.md`: rename `Unreleased` to the version and date; update the compare links at the bottom.
3. `README.md`: the upgrading section names the version users are upgrading from.
4. Tag `vX.Y.Z` on `main` and push the tag.
5. Versioning policy: while the library has no independent audit it stays at `v0.x`, where a minor bump may break compatibility (the 2026-10 rewrite ships as v0.3.0). `v1.0.0` marks the point where the public API is frozen after an external audit. A `v2` or later requires the module path to end in `/vN`.

## Specification Sources

- RFC 9591 and RFC 8032 as text from rfc-editor.org (`https://www.rfc-editor.org/rfc/rfc9591.txt`).
- IACR ePrint blocks scripted downloads; the Wayback Machine serves the PDFs: `https://web.archive.org/web/<year>id_/https://eprint.iacr.org/<paper>.pdf`. Convert with `pdftotext -layout` to get a greppable text; cite the protocol, figure, or section, not a page number.
- Papers: DKLS23 (2023/765), KOS15 (2015/546), Masny-Rindal (2019/706), KMOS21 (2019/1328), FROST (2020/852).
