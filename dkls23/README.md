# DKLS23 — Threshold ECDSA on secp256k1

Implementation of **"Threshold ECDSA in Three Rounds"** (Doerner, Kondi, Lee, shelat — IEEE S&P 2024).
Paper: https://eprint.iacr.org/2023/765.pdf

---

## File overview

| File | Protocol component | Paper |
|---|---|---|
| `params.go` | Security constants; gadget vector; `condUint32` branchless helper; `scalarInverse` (Fermat); domain separation tags | §8 |
| `commitment.go` | **FCom** (SHA-256 hash commitment); **FZero** (pairwise zero-sharing) | §3.1 |
| `ot.go` | **Masny-Rindal endemic base OT** (MR19 Figure 8, Diffie-Hellman instantiation) over secp256k1; scalar/point helpers | §8.1 |
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
fresh VOLE correlation from it. Nothing derived inside a signing session is
stored or reused: reusing an OT-extension batch across two sessions reveals
the difference of the signer's nonces and allows full key recovery.

Round structure (Protocol 3.6):

| Round | Message carries | Paper step |
|---|---|---|
| 1 | FCom commitment to R_i; Bob's OT-extension batch (corrections + consistency proof) for each counterparty | 5-6 |
| 2 | Decommitment of R_i; VOLE multiply message; Γ^u, Γ^v, ψ, pk_i | 7 |
| 3 | Signature fragments w_i, u_i after checks 1-3 | 8 |

A counterparty whose OT-extension batch fails the consistency check, whose
VOLE proof fails, or whose decommitment or check values are inconsistent is
blacklisted and excluded from all future sessions (step 8).

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

- `github.com/btcsuite/btcd/btcec/v2` — secp256k1 curve arithmetic (constant-time `ModNScalar`)
- `golang.org/x/crypto/sha3` — SHAKE-256 (PRG expansion, Fiat-Shamir)
- Standard library: `crypto/rand`, `crypto/sha256`, `crypto/subtle`, `math/big` (public hash reduction only)
