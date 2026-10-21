# Security

## Packages

This repository contains two threshold signature packages:

- **`dkls23/`** — Threshold ECDSA over secp256k1 (DKLS23 paper, IEEE S&P 2024)
- **`frost/`** — Threshold Schnorr / Ed25519 (IETF RFC 9591, FROST)

Both packages share the same threat model and security principles described
below, with protocol-specific details noted where they differ.

## Threat Model

Both packages implement t-of-n threshold signature protocols. A quorum of t
compromised shares can authorize signatures; security requires fewer than t
corrupt participants under the assumptions of each cited protocol. This is
not a claim that this implementation has been proven secure.
The following integration assumptions apply:

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

Both packages rotate shares without changing the master public key. The
proactive security of the complete implementation, including deletion of old
secrets and DKLS23's auxiliary-state refresh, still requires specialist review.

#### dkls23
- Shamir shares re-randomized using zero-constant Feldman VSS polynomials.
- Base-OT seeds (the only persistent OT material) and FZero seeds refreshed
  alongside shares (KMOS21). Fresh OT-extension batches and VOLE correlations
  are generated for each signing session and never reused across sessions.
- Successful `RefreshFinalize` calls record the local seed contribution,
  public key and party id under the setup's write lock. Reapplication on the
  live setup is rejected. The record is not serialized.

#### frost
- Shamir shares re-randomized using zero-constant Feldman VSS polynomials.
- Verification shares updated to match new secret shares.
- No VOLE/OT state (FROST has none). Simpler than dkls23 refresh.
- The same completed-contribution check applies to a live `SignerState`.

An epoch counter alone is not replay protection. The local records reject
concurrent and sequential duplicate finalization without requiring pending
contributions to remain on their original objects. They do not authenticate
peer transcripts or provide replay protection after a signer is re-created
from serialized state. The application must route messages to the correct
fresh session over authenticated channels, durably track applied refreshes,
and coordinate activation of the new epoch.

## Side-Channel Design and Evidence Limits

Secret arithmetic is implemented using constant-time primitives. Source
inspection, differential tests and functional vectors do not prove resistance
to side channels. Independent review of the backend integration and compiled
code on supported architectures remains a production gate.

### dkls23

- **Scalar arithmetic**: All secret scalar operations use btcec's constant-time
  `ModNScalar`. Modular inversion uses a constant-time Fermat's little theorem
  implementation (`scalarInverse`: `a^(q-2) mod q` via square-and-multiply with
  fixed public exponent). No `math/big` arithmetic is performed on secret values.
- **Point arithmetic and encoding**: `github.com/bytemare/secp256k1` v0.5.0
  provides a fixed 256-bit multiplication ladder, complete point addition
  and constant-time SEC1 coordinate encoding. btcec's `NonConst` point
  operations are not used in production protocol code. Final ECDSA
  verification may use variable-time operations because its inputs are public.
- **FZero reduction**: 64-byte PRF outputs are secret. Their reduction uses
  `ModNScalar` on both 256-bit halves and the existing `2^256 mod q` gadget
  entry. It computes exactly the former reduction without `math/big`.
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
- **Zeroization**: Explicit clears overwrite scalar objects and selected
  temporary buffers, including the curve adapter's scalar bytes. They do not
  guarantee deletion of compiler, backend or garbage-collector copies.

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
- **Nonce reuse prevention**: Round 2 holds the signer's write lock while
  checking and consuming nonce state (RFC 9591 §5.1–5.2). Copies of a state
  returned by `SignRound1` share one consumption record with its own mutex,
  including when used with equivalent signer wrappers. States check the
  matching key, participant set and epoch; local nonces must
  match the stored commitment. These checks do not make copied raw secret
  nonce material safe to reuse.

## Session Lifetime and Persistence

- Treat exported state fields as read-only during their lifetime. Do not
  copy mutex-bearing signer/setup objects or share their mutable fields
  between independent wrappers. The locks cover library calls, not direct
  field mutation by the application.
- Rejected signer-state imports leave the active signer unchanged. DKLS23
  private round-state imports also validate all fields before replacement.
  Regression tests finish the active signing or refresh operation after
  rejected imports and verify the resulting signatures independently.
- Retain the matching key, epoch, participant set and session progress with
  private signing or refresh state. Existing restoration behavior is retained;
  signer object identity is not an authorization check. Never use a nonce pair
  or a DKLS23 OT/VOLE correlation in more than one signing session.
- DKLS23 must reserve a globally unique session id durably before sending its
  first round output. Before sending later outputs, persist session progress
  and blacklist changes. If persistence fails, send nothing and abort the
  session. Restoring state must not roll back completed rounds or recycle ids.
- Encrypted serialization does not supply atomic writes, durable reservation,
  rollback detection or coordination of the same ephemeral secrets across
  copies. Supply transactional storage for those properties. Snapshot
  restoration and RNG-state cloning must not cause session or nonce reuse.
- On refresh, quiesce old signing sessions, authenticate the refresh session,
  agree on success, and persist the new epoch consistently across the group.
  A local one-use guard cannot solve a partial distributed commit or recovery
  from old backups. Recovery must not silently activate mixed epochs.
- The examples demonstrate protocol calls and encryption, not a production
  storage or recovery system. Their colocated encryption keys and direct
  `os.WriteFile` calls do not meet these requirements.

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
Additional tests exercise concurrent nonce consumption and refresh finalization,
copied and restored state, stale epochs, exact FZero reduction, and differential
curve operations. These are regression checks, not an independent audit.

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
  session to use a fresh `sigid`. `SignerSetup` records the last completed
  round of every session id used in the current epoch and rejects a reuse
  with `SessionIDReusedError`; each round of a session can run exactly once.
  The record is persisted with the setup and cleared by a refresh, which
  re-keys everything a session id feeds into. Callers should still generate
  a fresh random id per session (as the example does with `node.SessionID`);
  the check is a backstop, and two setups restored from the same snapshot
  cannot see each other's records.
- **Peer transcript replay and distributed recovery**: Local lifetime checks
  do not provide reliable broadcast, fresh authenticated peer transcript
  envelopes, distributed commit, or backup rollback protection. Implement
  these at the integration layer and test them against crashes and replay.
- **Private state association**: DKLS23's existing round-state JSON does not
  carry a key or epoch binding. Callers must restore it with its matching
  setup and progress record. This remains open as AUDIT.md FU-MED-6; the
  security fixes retain the existing formats and restoration behavior.
- **No independent human audit**: Both packages were first reviewed by an
  automated audit (Claude Code, Anthropic Claude Opus 4.6). A 2026-10-16
  follow-up review (Claude Code, Anthropic Claude Fable 5.1) found that this
  first audit had missed a critical
  key-recovery flaw in dkls23 (reuse of the OT-extension batch across signing
  sessions) and several protocol deviations from the cited specifications.
  Further hardening and remaining assurance gaps are recorded in
  [`AUDIT.md`](AUDIT.md) and the production review gates below.
  Automated review is
  not a substitute for an independent third-party audit by a firm specializing
  in MPC protocols, and the code has not been formally verified.

## Production Review Gates

- Independent specialist review of the exact release commit, including
  DKLS23/KOS15/MR19, FROST DKG and signing, refresh, encoding and persistence;
  verification of the resulting fixes by the reviewers.
- A step-by-step refresh conformance review against the cited papers and
  their corruption/erasure assumptions. Correlation tests alone do not
  establish proactive security.
- Independent review of the curve backend integration and compiled secret
  data paths on supported architectures. Functional tests do not establish
  timing or cache side-channel resistance.
- Deployment-specific validation of custody, authorization, authenticated
  session routing, durable state, recovery and protection against rollback
  or independently activated copies. Test failures at storage and transfer
  boundaries using disposable keys.
- Full CI on the final release candidate, sustained adversarial testing,
  reviewed dependencies, release provenance and a vulnerability-response
  process. Keep the published protocol vectors unchanged.

## Responsible Disclosure

If you discover a security vulnerability in this project, please report it
through GitHub Security Advisories (private vulnerability reporting):

<https://github.com/chrisalmeida/go-mpc/security/advisories/new>

Do not open a public issue for security vulnerabilities.

## Dependencies

| Dependency                          | Used by | Purpose                                                                               |
| ----------------------------------- | ------- | ------------------------------------------------------------------------------------- |
| `github.com/bytemare/secp256k1`     | dkls23  | Point multiplication, complete addition and SEC1 encoding; pinned v0.5.0, integration audit pending |
| `github.com/btcsuite/btcd/btcec/v2` | dkls23  | Constant-time scalar arithmetic and public ECDSA verification |
| `filippo.io/edwards25519`           | frost   | Ed25519 curve operations (constant-time scalar and point arithmetic, RFC 8032 encoding) |
| `golang.org/x/crypto`               | dkls23  | SHAKE-256 (OT hashing, Fiat-Shamir challenges, VOLE proofs)                           |
| `github.com/stretchr/testify`       | both    | Test assertions only (not used in production code)                                    |
