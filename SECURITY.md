# Security

## Packages

This repository contains two threshold signature packages:

- **`dkls23/`** — Threshold ECDSA over secp256k1 (DKLS23 paper, IEEE S&P 2024)
- **`frost/`** — Threshold Schnorr / Ed25519 (IETF RFC 9591, FROST)

Both packages share the same threat model and security principles described
below, with protocol-specific details noted where they differ.

## Threat Model

Both packages implement t-of-n threshold signature protocols with honest majority.
The following assumptions apply:

- All parties communicate over authenticated point-to-point channels (e.g., TLS
  or Noise Protocol Framework). Neither package provides a transport
  layer — callers must ensure channel authentication and confidentiality.
- The master secret key is never reconstructed in a single location. Each party
  holds only a Shamir secret share.

### Cheating Detection

#### dkls23

Cheating parties are detected at multiple protocol stages:

- **OT-extension consistency check**: Every signing session runs a fresh
  OT-extension batch per counterparty (DKLS23 Functionality 5.1 requires a
  fresh session id per batch). The batch carries a KOS15 consistency proof
  with a Fiat-Shamir challenge (paper §5.1); a receiver who sends
  inconsistent corrections is caught by the sender in round 2 and blacklisted.
- **VOLE consistency check**: Malicious correlation values are caught via a
  SHAKE-256 proof verified with constant-time comparison
  (`subtle.ConstantTimeCompare`).
- **R-commitment decommitment**: Parties commit to nonce shares in signing
  round 1 and decommit in round 2. Inconsistencies are detected and the
  cheating party is identified.
- **Blacklisting**: Detected cheaters are permanently blacklisted via
  `SignerSetup.Blacklist` and rejected from all future signing sessions.

#### frost

Cheating detection in FROST is simpler due to Schnorr's linearity:

- **DKG proof of knowledge**: Each party proves knowledge of its polynomial's
  constant term with a Schnorr proof bound to a context string (FROST paper
  Figure 1); proofs are verified before any share is sent, which prevents
  rogue-key attacks on the group key.
- **Feldman VSS verification**: Each party's DKG share is verified against
  broadcast Feldman commitments. Inconsistent shares are detected.
- **Element validation**: Every received group element is decoded per RFC
  9591 §6.1 (canonical encoding, not the identity, in the prime-order
  subgroup).
- **Signature share verification**: The aggregator can verify each individual
  signature share (`z_i * B == D_i + rho_i * E_i + c * lambda_i * PK_i`),
  enabling identifiable abort — the specific misbehaving signer is identified.
- **Blacklisting**: Detected cheaters can be permanently blacklisted via
  `SignerState.Blacklist`. Per RFC 9591 §5.4 and §7, attribution assumes an
  authenticated channel and a Coordinator that does not equivocate: a
  Coordinator that distributes inconsistent commitment lists makes an honest
  signer's share fail verification, so automatic blacklisting is only safe
  with an honest or reliable-broadcast Coordinator.

### Proactive Key Refresh

Both packages support proactive key share refresh — rotating shares without
changing the master public key. This limits the exposure window if a share
is compromised.

#### dkls23
- Shamir shares re-randomized using zero-constant Feldman VSS polynomials.
- Base-OT seeds (the only persistent OT material) and FZero seeds refreshed
  alongside shares (KMOS21). VOLE correlations are never persisted: they are
  regenerated inside every signing session.
- Refresh sessions tracked by epoch to prevent replay.

#### frost
- Shamir shares re-randomized using zero-constant Feldman VSS polynomials.
- Verification shares updated to match new secret shares.
- No VOLE/OT state (FROST has none). Simpler than dkls23 refresh.
- Refresh sessions tracked by epoch to prevent replay.

## Constant-Time Guarantees

All operations on secret values are designed to execute in constant time,
preventing timing side-channel attacks on shared hardware.

### dkls23

- **Scalar arithmetic**: All secret scalar operations use btcec's constant-time
  `ModNScalar`. Modular inversion uses a constant-time Fermat's little theorem
  implementation (`scalarInverse`: `a^(q-2) mod q` via square-and-multiply with
  fixed public exponent). No `math/big` arithmetic is performed on secret values.
- **VOLE Beta selection**: Bob's secret binary vector β is never used as a
  branch condition. All β-dependent operations use branchless multiply-by-mask
  (`condUint32(β) * value`) or `subtle.ConstantTimeCopy` for byte selection.
- **OT extension**: the KOS15 consistency check is computed in constant-time
  GF(2^128) arithmetic (`gf128.go`); the sender's choice bits σ and the
  receiver's choice bits are never branch conditions.
- **Base OT**: the receiver's choice bits select between precomputed values
  with `subtle.ConstantTimeCopy`.
- **Commitment verification**: FCom opening and VOLE proof checks use
  `subtle.ConstantTimeCompare`.
- **Zeroization**: Ephemeral secrets are zeroized via `ModNScalar.Zero()`
  (deterministic, not subject to GC interference).

The only remaining `math/big` usage is `reduce64Public`, which reduces 64-byte
public hash outputs (Fiat-Shamir challenges, FZero hashes) modulo q. These
are derived from public data and are not timing-sensitive.

### frost

- **Scalar arithmetic**: All secret scalar operations use `filippo.io/edwards25519`
  constant-time `Scalar` methods (`Add`, `Multiply`, `Subtract`). Modular
  inversion uses a constant-time Fermat's little theorem implementation
  (`scalarInverse`: `a^(L-2) mod L` via square-and-multiply with fixed public
  exponent). No `math/big` arithmetic is performed on secret values.
- **Nonce generation**: Hedged via RFC 9591's `nonce_generate`:
  `H3(random_bytes(32) || secret)`. Mixes CSPRNG output with the secret key
  to protect against weak RNG.
- **Commitment verification**: DKG share commitments use `subtle.ConstantTimeCompare`.
- **Zeroization**: Signing nonces (`HidingNonce`, `BindingNonce`) are zeroized
  to the zero scalar after `SignRound2` computation. The `nonceGenerate` input
  buffer (containing the secret key) is explicitly zeroed after hashing.
- **Nonce reuse prevention**: `Round1State.consumed` flag prevents a second call
  to `SignRound2` with the same nonces. Reuse would enable full key recovery.

## Test Coverage

Both packages maintain comprehensive test suites with 90%+ statement coverage:

- **dkls23**: fuzz targets for every wire type, unmarshal error cases for
  every wire type, race-detector clean.
- **frost**: fuzz targets for every wire type, unmarshal error cases for
  every wire type, RFC 9591 Appendix E.1 test vectors, race-detector clean.

Edge-case tests cover malicious inputs (corrupted commitments, inconsistent
OT-extension batches, forged DKG proofs, non-canonical scalars and points,
small-order points, truncated shares), nonce reuse prevention, independence
of VOLE messages across signing sessions, post-persistence functional
round-trips, and identifiable abort.

## Known Limitations

- **Memory retention**: Go's garbage collector may retain copies of
  intermediate stack values after zeroization. No memory pinning or `mlock`
  is used. (Applies to both packages.)
- **Random oracle model**: dkls23 uses SHAKE-256; frost uses SHA-512. Both
  are modeled as random oracles in their respective protocol security proofs.
- **Physical attacks**: No protection is provided against physical
  side-channel attacks (power analysis, electromagnetic emanation, etc.).
  (Applies to both packages.)
- **Session identifiers**: DKLS23 Protocol 3.6 step 4 requires every signing
  session to use a fresh `sigid`. The library does not track used session
  identifiers; callers must generate a fresh random one per session (as the
  example does with `node.SessionID`).
- **No independent human audit**: Both packages were first reviewed by an
  automated audit (Claude Code, Anthropic Claude Opus 4.6). A 2026-10-16
  follow-up review (Claude Code, Anthropic Claude Fable 5.1) found that this
  first audit had missed a critical
  key-recovery flaw in dkls23 (reuse of the OT-extension batch across signing
  sessions) and several protocol deviations from the cited specifications; all
  are resolved and documented in [`AUDIT.md`](AUDIT.md). Automated review is
  not a substitute for an independent third-party audit by a firm specializing
  in MPC protocols, and the code has not been formally verified.

## Responsible Disclosure

If you discover a security vulnerability in this project, please report it
through GitHub Security Advisories (private vulnerability reporting):

<https://github.com/chrisalmeida/go-mpc/security/advisories/new>

Do not open a public issue for security vulnerabilities.

## Dependencies

| Dependency                          | Used by | Purpose                                                                               |
| ----------------------------------- | ------- | ------------------------------------------------------------------------------------- |
| `github.com/btcsuite/btcd/btcec/v2` | dkls23  | secp256k1 curve operations (constant-time scalar arithmetic and point multiplication) |
| `filippo.io/edwards25519`           | frost   | Ed25519 curve operations (constant-time scalar and point arithmetic, RFC 8032 encoding) |
| `golang.org/x/crypto`               | dkls23  | SHAKE-256 (OT hashing, Fiat-Shamir challenges, VOLE proofs)                           |
| `github.com/stretchr/testify`       | both    | Test assertions only (not used in production code)                                    |
