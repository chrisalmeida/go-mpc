# DKLS23 — Threshold ECDSA on secp256k1

Implementation of **"Threshold ECDSA in Three Rounds"** (Doerner, Kondi, Lee, shelat — IEEE S&P 2024).
Paper: https://eprint.iacr.org/2023/765.pdf

---

## File overview

| File | Protocol component | Paper |
|---|---|---|
| `params.go` | Security constants; gadget vector; `condUint32` branchless helper; `scalarInverse` (Fermat); domain separation tags | §8 |
| `commitment.go` | **FCom** (SHA-256 hash commitment); **FZero** (pairwise zero-sharing) | §3.1 |
| `ot.go` | **Masny-Rindal endemic base OT** (MR19 Figure 8, Diffie-Hellman instantiation) over secp256k1 | §8.1 |
| `curve.go` | Constant-time secp256k1 point operations and compressed SEC1 encoding; protocol group operations unchanged | Protocols 3.6, 7.1; MR19 Appendix D.1 |
| `ot_extension.go` | **KOS15 OT extension** realizing FEOTE(Zq^{l+rho}, xi=416) with a one-message Fiat-Shamir consistency check; one fresh batch per signing session | §5.1 |
| `gf128.go` | Constant-time GF(2^128) multiplication for the OT-extension consistency check | §5.1 |
| `vole.go` | **RVOLE** (Protocol 5.2) — Fiat-Shamir proof, Bob verification, constant-time mu check | §5 |
| `dkg.go` | **Relaxed KeyGen** (Protocol 7.1) — commit-then-reveal Feldman VSS, Lagrange coefficients, input validation | §7 |
| `sign.go` | **Threshold ECDSA** (Protocol 3.6) — 3-round signing, per-session VOLE, consistency checks, blacklisting | §3 |
| `refresh.go` | **Proactive refresh** (KMOS21) — re-randomizes shares, base-OT seeds, FZero seeds | |
| `persistence.go` | JSON serialization and pluggable encrypted storage for `SignerSetup` | |
| `encoding.go` | Custom JSON marshaling for all protocol message types (versioned `SignerSetup` wire format) | |
| `setup_messages.go` | Wire types for the one-time base OT and FZero setup messages | |
| `errors.go` | Typed errors: `CheatingPartyError`, `InvalidInputError`, `CorruptStateError`, `BlacklistedPartyError` | |

---

## What is persistent and what is per session

Per DKLS23 §8.2 the one-time setup between each pair of parties consists of
the λc base OTs (both directions) and an FZero seed. These are the only
pairwise values stored in `SignerSetup`.

Every signing session runs, for every counterparty, a fresh OT-extension
batch under a fresh session id (Functionality 5.1 requires it) and derives a
fresh VOLE correlation from it. Session-derived OT/VOLE state is not placed
in the long-term setup or reused across sessions: reusing a batch reveals
the difference of the signer's nonces and allows full key recovery.

Existing setup and private round-state JSON remain usable with the matching
session progress. Callers must retain the correct key/epoch association and
durably reserve fresh session ids before transmitting outputs. Serialization
alone does not prevent rollback or reuse of the same secrets across copies.

Refresh finalization records completed local contributions on the live setup
and rejects repeats. This local record is not serialized. Pending contribution
restoration is unchanged; durable replay protection, peer transcript freshness
and consistent epoch activation remain caller responsibilities.

---

## Protocol flow

| Phase | Calls | Messages | Paper |
|---|---|---|---|
| DKG round 1 | `DKGRound1` | broadcast FCom commitments (nothing revealed) | 7.1 step 2 |
| DKG round 2 | `DKGRound2` (needs every peer's round 1) | Feldman commitments + salt, one share + salt per peer | 7.1 step 3 |
| DKG finalize | `DKGFinalize` | — | 7.1 step 4 |
| Base OT (per directed pair, one-time) | `BaseOTReceiverRound1` → `BaseOTSenderRound2` → `BaseOTReceiverFinalize` | receiver's (r_0, r_1) pairs; sender's (m_0, m_1) pairs | §8.1 |
| FZero seed (per pair, one-time) | `FZeroSetupRound1` → `FZeroSetupFinalize` | seed commitment; seed + salt | §3.1 |
| Sign round 1 | `SignRound1` | FCom commitment to R_i; the session's OT-extension batch for each counterparty | 3.6 steps 5-6 |
| Sign round 2 | `SignRound2` (verifies each batch, derives the VOLE) | decommitment of R_i; VOLE multiply message; Γ^u, Γ^v, ψ, pk_i | 3.6 step 7 |
| Sign round 3 | `SignRound3` (checks 1-3) | signature fragments w_i, u_i | 3.6 step 8 |
| Combine | `ComputeRx`, `SignCombine` (verifies the signature) | — | 3.6 step 10 |
| Refresh | `RefreshRound1` → `RefreshRound2` → `RefreshFinalize` | Feldman commitments, seed commitments; shares + seeds | KMOS21 |

A counterparty whose OT-extension batch fails the consistency check, whose
VOLE proof fails, or whose decommitment or check values are inconsistent is
blacklisted (step 8). Future signing rounds reject that party while the entry
is retained; callers must persist the blacklist and prevent rollback.

[SECURITY.md](../SECURITY.md#evidence-and-test-coverage) maps implementation
claims to regression tests and distinguishes source inspection of timing
properties from independent side-channel evidence.

---

## Security parameters

| Parameter | Value | Meaning |
|---|---|---|
| kappa | 256 | Bit-length of secp256k1 order |
| lambda_c | 128 | Computational security parameter |
| lambda_s | 80 | Statistical security parameter |
| Xi | 416 | OT instances per VOLE (kappa + 2*lambda_s) |
| XiExt | 672 | OT-extension batch length including the KOS pad (Xi + 2*lambda_c; the statistical parameter is raised to lambda_c for the Fiat-Shamir challenge, paper §5.1) |
| Rho | 2 | VOLE check elements (ceil(kappa/lambda_c)) |
| Ell | 2 | VOLE inputs per signing session: {r_i, sk_i} |
| SaltLen | 32 bytes | FCom commitment salt (2*lambda_c / 8) |

---

## Dependencies

- `github.com/bytemare/secp256k1` v0.5.0 — constant-time point multiplication, complete addition, and SEC1 encoding; independent integration audit pending
- `github.com/btcsuite/btcd/btcec/v2` — constant-time `ModNScalar` arithmetic and independent verification of final ECDSA signatures
- `golang.org/x/crypto/sha3` — SHAKE-256 (PRG expansion, Fiat-Shamir)
- Standard library: `crypto/rand`, `crypto/sha256`, `crypto/subtle`
