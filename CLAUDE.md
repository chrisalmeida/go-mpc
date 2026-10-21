# CLAUDE.md

## Project Overview

Threshold signing library in Go. Implements two protocols:

- **DKLS23** — Threshold ECDSA over secp256k1 ([DKLS23 paper](https://eprint.iacr.org/2023/765), IEEE S&P 2024)
- **FROST** — Threshold Schnorr / Ed25519 ([RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html), FROST(Ed25519, SHA-512))

- **Module**: `github.com/chrisalmeida/go-mpc`
- **Go**: 1.25+

## Build & Test

```bash
make test          # run all tests
make test-race     # run with race detector (what CI runs)
make bench         # run benchmarks
make cover         # show coverage summary
make lint          # gofmt + go vet + staticcheck
make fuzz          # run every fuzz target briefly
make vuln          # govulncheck
make examples      # build and run both demos
make ci            # full CI pipeline locally
```

Or directly:
```bash
go test ./...
go test -race -timeout 120s ./...
```

## Code Layout

- `dkls23/` — Core protocol package. All cryptographic code lives here.
  - `dkg.go` — Commit-then-reveal Feldman VSS distributed key generation (Protocol 7.1)
  - `sign.go` — 3-round threshold signing (Protocol 3.6); round 1 carries a fresh OT-extension batch per counterparty, round 2 derives the session's VOLE from it
  - `refresh.go` — Proactive key share refresh (KMOS21); re-randomizes shares, base-OT seeds, FZero seeds
  - `vole.go` — Vector OLE (Protocol 5.2), instantiated fresh per signing session
  - `ot.go` — Masny-Rindal endemic base OT (one-time setup; the only persistent OT material)
  - `ot_extension.go` / `gf128.go` — KOS15 OT extension with Fiat-Shamir consistency check (paper §5.1) and its GF(2^128) arithmetic
  - `commitment.go` — FCom and FZero primitives
  - `persistence.go` — AES-256-GCM encrypted serialization
  - `encoding.go` — Wire format JSON marshaling
  - `errors.go` — Typed error categories
  - `params.go` — Security constants and package-level docs
- `frost/` — FROST threshold Schnorr / Ed25519 package (RFC 9591).
  - `keygen.go` — Feldman VSS distributed key generation (2 rounds) with the FROST paper's Schnorr proof of knowledge of each constant term, verified before shares are sent; received elements go through `deserializeElement` (RFC 9591 §6.1)
  - `sign.go` — 2-round threshold signing + aggregation
  - `refresh.go` — Proactive key share refresh
  - `verify.go` — Cofactored Ed25519 verification
  - `hash.go` — H1-H5 domain-separated hash functions
  - `persistence.go` — Encrypted serialization
  - `encoding.go` — Wire format JSON marshaling
  - `errors.go` — Typed error categories
  - `params.go` — Ciphersuite constants and package-level docs
- `example/` — Runnable demos
  - `shared/` — AES-256-GCM encryptor shared by both demos
  - `dkls23/` — 3-of-3 DKLS23 ECDSA demo (`cd example/dkls23 && go run .`)
  - `frost/` — 2-of-3 FROST Ed25519 demo (`cd example/frost && go run .`)
  - Separate `go.mod` with `replace github.com/chrisalmeida/go-mpc => ../`
  - Not included in `go test ./...` — run and test independently

## Conventions

- Error messages: `"dkls23 FunctionName: description"` or `"frost FunctionName: description"`
- Formatting: `gofmt`, `go vet`, `staticcheck` must all pass
- Tests: maintain 90%+ coverage, always run with `-race`
- Dependencies: keep minimal — only add if cryptographically necessary
- Exported types have GoDoc comments referencing paper sections where applicable

## Test Performance

CI runs on resource-constrained GitHub Actions runners where crypto-heavy tests can be 3–5× slower than local.

### dkls23 test patterns

1. **Parallel base-OT setup** — `buildSetups()` in `helpers_test.go` runs pairwise base-OT/FZero setup concurrently across goroutines (one per party pair).
2. **Cached 3-of-3 fixture** — `fullSetup(t)` builds the expensive DKG+base-OT setup once via `sync.Once` and deep-copies via JSON for each caller. Use `fullSetup(t)` for any test that needs a standard 3-of-3. Only call `setupSigners(t, ids, threshold)` for non-standard configs (2-of-3, 2-of-2, etc.).
3. **Session helpers** — `runRound1`/`runRound2`/`runRound3`/`runSession` in `sign_test.go` return a `signingSession` whose messages can be tampered with between rounds; `runSigning` wraps a full session plus `SignCombine`. `runVOLEPairwise`/`runVOLESession` in `helpers_test.go` run one OT-extension batch + VOLE sampling over fresh or given base-OT seeds.
4. **`t.Parallel()`** — All tests that do crypto work (VOLE, OT, signing, refresh) must include `t.Parallel()` so they overlap. This is safe because `fullSetup` returns independent deep copies and `setupSigners`/`buildSetups` create fresh state.

When adding new dkls23 tests:
- If the test needs a 3-of-3 setup, use `fullSetup(t)` (cached) — **not** `setupSigners(t, []int{1,2,3}, 3)`.
- Add `t.Parallel()` to any test that takes >100ms or calls `fullSetup`/`setupSigners`/`runVOLEPairwise`.
- Never share mutable state between parallel tests; each test should own its setup.
- Never persist or reuse `VOLEAliceState`/`VOLEBobState` across sessions in a test fixture; only base-OT seeds are reusable.

### frost test patterns

1. **Cached 3-of-3 fixture** — `fullSetup(t)` in `helpers_test.go` runs DKG once via `sync.Once` and deep-copies via JSON for each caller. FROST has no VOLE/OT setup, so the DKG is fast, but the cache follows the same pattern for consistency.
2. **`fullSign(t, keyShares, signers, msg)`** — Runs a complete signing session (round 1 → round 2 → aggregate with share verification). Use this for any test that needs a valid signature.
3. **`buildDKG(allIDs, threshold)`** — Runs a fresh DKG for non-standard configs (2-of-3, 2-of-2). Use instead of `fullSetup` when testing non-3-of-3 setups.
4. **`t.Parallel()`** — Same rules as dkls23: add to any test doing crypto work.

When adding new frost tests:
- If the test needs a 3-of-3 setup, use `fullSetup(t)` (cached) — **not** `buildDKG([]int{1,2,3}, 3)`.
- Add `t.Parallel()` to any test that takes >100ms or calls `fullSetup`/`buildDKG`/`fullSign`.
- Never share mutable state between parallel tests; each test should own its setup.

## Rules for Protocol Changes

These rules exist because the 2026-10-16 review found that earlier code had drifted from the specifications in ways that were exploitable (see AUDIT.md). They apply to every change under `dkls23/` and `frost/`.

1. **Implement the cited specification; never invent.** dkls23 follows the DKLS23 paper (ePrint 2023/765) and the papers it delegates to: KOS15 (ePrint 2015/546) for the OT extension, Masny-Rindal (ePrint 2019/706) for the base OT, KMOS21 (ePrint 2019/1328) for refresh. frost follows RFC 9591 and, for the DKG the RFC does not specify, the FROST paper (ePrint 2020/852). Every protocol function's GoDoc names the protocol, figure, or section it implements. Where a spec leaves a detail open (an encoding, a domain tag, a hash input order), choose the simplest unambiguous option and document it in the GoDoc and in AUDIT.md.
2. **Only one-time setup material is persistent in dkls23.** `SignerSetup` stores base-OT seeds and FZero seeds. OT-extension batches and VOLE correlations are per signing session and must never be stored, cached, or reused; reuse leaks nonce differences and the key.
3. **Validate everything received before use.** Lengths, canonical encodings, points on the curve, and for frost the full RFC 9591 §6.1 `DeserializeElement` rules (non-identity, prime-order subgroup) via `deserializeElement`. Misbehaviour is attributed to a party with `CheatingPartyError` and the party is blacklisted only where the spec says attribution is sound.
4. **No secret-dependent control flow or memory access.** Secret bits select with masks or `subtle.ConstantTimeCopy`; secret scalars use the constant-time scalar types; `math/big` only on public values; ephemeral secrets are zeroized.
5. **Versioned wire formats.** Any change to a persisted type bumps the package's wire-format version constant and keeps a rejection test for old or missing versions.
6. **Tests prove behaviour, not absence of errors.** New protocol code needs: a correctness test, a tampering test for each received field showing rejection and attribution, and where vectors exist a vector test. `frost/vectors_test.go` (RFC 9591 Appendix E.1) and `dkls23` `TestSignSessionsUseFreshVOLE` must keep passing unchanged.
7. **Documentation follows the code.** Security-relevant findings get an ID in AUDIT.md; SECURITY.md claims must stay true; CHANGELOG.md gets an entry; breaking changes are listed in the README's upgrading section.

Spec sources: RFCs from rfc-editor.org as text. IACR ePrint blocks scripted downloads; the Wayback Machine serves the PDFs (`https://web.archive.org/web/<year>id_/https://eprint.iacr.org/<paper>.pdf`), and `pdftotext -layout` gives a greppable text.

## Release Checklist

1. `make ci` green on the release commit.
2. CHANGELOG.md: rename `Unreleased` to the version and date, update the compare link.
3. README.md: the upgrading section names the version being upgraded from.
4. Tag `vX.Y.Z` on `main`. Go's semantic import versioning means a v2 or later requires the module path to end in `/vN`; v1 does not.

## Security-Sensitive Areas

All code in `dkls23/` and `frost/` is security-critical.

### dkls23
- DKG (Feldman VSS commitment verification)
- Signing (nonce generation, consistency checks)
- VOLE/OT (oblivious transfer correctness)
- Key refresh (share re-randomization)
- Persistence (encryption key handling)

### frost
- DKG (proof-of-knowledge verification, Feldman VSS commitment verification, commitment count validation)
- Element deserialization (`deserializeElement`: canonical encoding, non-identity, prime-order subgroup per RFC 9591 §6.1)
- RFC 9591 Appendix E.1 vectors in `vectors_test.go` must keep passing exactly
- Signing (hedged nonce generation via `nonce_generate`, nonce reuse prevention)
- Aggregation (signature share verification for identifiable abort)
- Key refresh (zero-constant polynomial share re-randomization)
- Verification (cofactored equation, non-canonical point/scalar rejection)
- Persistence (encryption key handling)

Ephemeral secrets (polynomial coefficients, nonce shares, Lagrange coefficients) are zeroized after use in both packages.

## CI

GitHub Actions (`.github/workflows/ci.yml`) runs on push to `main` and all PRs: `go vet` → `staticcheck` → `go test -race` → coverage summary. Reproduce locally with `make ci`.
