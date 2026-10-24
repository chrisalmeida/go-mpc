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
| `validation.go` | Validate local setup, selected peers and locally recomputable private signing state before use | Protocols 3.6, 5.2 |
| `setup_messages.go` | Wire types for the one-time base OT and FZero setup messages | |
| `state_encoding.go` | Bound private signing and refresh checkpoints; strict versioned refresh JSON | Local persistence format |
| `session.go` | `SessionCodec.Signing` / `.Refresh` callbacks using encrypted authoritative state | Existing signing and refresh rounds |
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
The module's `session` package implements that reservation and recovery
discipline over a caller-supplied transactional store; `store_test.go` drives
a full signing session through it.

Signing checks participant membership and both directions of base OT plus
FZero material for every selected peer before returning round-1 output.
Setup for unselected peers may remain absent. Later rounds check the local
nonce opening, FZero value, VOLE choice/scalar relation, masked share and
required peer-map entries. Failures of these local checks return
`CorruptStateError` before peer messages are evaluated. These checks cannot establish
the origin or freshness of a restored document. See AUDIT.md FU-MED-10.

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

Run `go -C example/cold-dkls23 run . demo DIRECTORY` from the repository root
with `MPC_WRAPPING_KEY` set to a 32-byte hex demo key and an empty directory.
`init`, `request`, `round` and `combine` also run individually; `--help` and the
[root README](../README.md) show the file flow. Each device retains its encrypted
private state; the coordinator routes per-recipient protocol messages and combines
without a secret key. `TestColdDKLSCommandsRestartRelocateAndRecoverOutput` checks
these commands across restarts and relocation, lost file delivery and cached
retry, with independent ECDSA verification. See AUDIT.md FU-LOW-9.

`MarshalRound1Encrypted` / `MarshalRound2Encrypted` bind the existing round state
to its setup and signing ID. New envelope payloads preserve arbitrary operation
ID bytes with base64; legacy plaintext JSON remains unchanged. These ephemeral
OT/VOLE values belong to one operation only. Stopping before the message after
round 2 requires `SessionSignInput.AllowPreSigning`; the protocol still consumes
the message only at round 3, under the §3.3 assumptions already documented above.
