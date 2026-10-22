# Security Audit Report: dkls23 + frost

**Packages**: `github.com/chrisalmeida/go-mpc/dkls23`, `github.com/chrisalmeida/go-mpc/frost`
**Scope**: All production source files in `dkls23/` and `frost/`
**Date**: 2026-04-03 (frost), 2026-03-27 (dkls23 original)
**Auditor**: Automated cryptographic review (not a substitute for an independent third-party audit)

**2026-10-21 hardening addendum**: see FU-HIGH-2, FU-HIGH-3 and
FU-MED-5 through FU-MED-9 and FU-LOW-7 below. These include implementation fixes, an open
state-association finding and regression evidence from an automated source
review, not an independent audit or a
production-security certification. Remaining gates are in
[SECURITY.md](SECURITY.md#production-review-gates).

---

## Executive Summary

This repository contains two threshold signature packages:

- **dkls23**: Threshold ECDSA (DKLS23 paper, IEEE S&P 2024) over secp256k1.
- **frost**: Threshold Schnorr / Ed25519 (IETF RFC 9591, FROST) over edwards25519.

The dkls23 package demonstrates strong security practices: constant-time
`ModNScalar` arithmetic, branchless VOLE Beta selection, deterministic
zeroization, and defense-in-depth signature verification. The frost package
leverages `filippo.io/edwards25519` for constant-time scalar and point
arithmetic, implements RFC 9591's hedged nonce generation, cofactored
verification, and identifiable abort via individual share verification.
Both packages maintain 90%+ test coverage with comprehensive fuzz testing,
unmarshal error testing, and malicious input handling.

**dkls23 review** identified **1 high**, **4 medium**, and **5 low** severity
findings. **All 10 findings have been resolved.**

**frost review** identified **0 high**, **2 medium**, and **2 low** severity
findings. **All 4 findings have been resolved.**

**2026-10-16 follow-up review** (see the next section) found that the
original review was incomplete: it identified **1 critical**, **1 high**,
**4 medium**, and **6 low** additional findings, including a confirmed
full-key-recovery attack on dkls23 that was demonstrated with a
proof-of-concept test. All of them are resolved in the current source.

---

## 2026-10-16 Follow-up Review

**Scope**: all production source in `dkls23/` and `frost/`, reviewed against
the DKLS23 paper (ePrint 2023/765, Protocols 3.6, 5.2, 7.1, §5.1, §8.1-8.2),
RFC 9591, the FROST paper (ePrint 2020/852, Figure 1) and MR19 (ePrint
2019/706, Figure 8, Appendix D.1).
**Reviewer**: Claude Code (Anthropic Claude Fable 5.1); automated review,
not a substitute for an independent third-party audit.
**Method**: independent source review, exploit construction, and
re-implementation of the deviating components to match the cited
specifications. The exploit for FU-CRIT-1 was written as a Go test and run
against the code as it stood; it recovered the master private key.

### FU-CRIT-1: VOLE correlation reused across signing sessions — RESOLVED

**File**: `vole.go` (`VOLEAliceMultiply`), `sign.go`, `persistence.go`
**Severity**: Critical
**Category**: Key recovery

The OT extension was run once during pairwise setup and its outputs
(`VOLEAliceState.Alpha0/Alpha1`, `VOLEBobState.Gamma`) were persisted and
reused by every signing session. Alice's multiply message is
`ã = α0 − α1 + a` with `a = (r_i, sk_i)`, so the difference of two sessions'
messages equals the difference of her nonces. A co-signer, who also knows its
own nonces, therefore learns the difference of the two combined ECDSA nonces
and recovers the private key from two signatures by solving two linear
equations. A proof-of-concept test (2-of-2, party 2 passive) recovered the
key on the first run. The library's own test suite exercised exactly this
usage (`TestSign3of3MultipleMessages`).

**Resolution**: Per Functionality 5.1 (fresh `sid` per batch) and §8.2 ("setup
for endemic OT extension is performed once per pair of parties, and reused
thereafter in all instances of the protocol realizing FEOTE"), only the λc
base-OT seeds are persistent. `SignRound1` now runs a fresh OT-extension
batch for every counterparty (carried in `Round1Msg.OTExt`, realizing
`(sample, sid)` of Protocol 3.6 step 6) and `SignRound2` derives the
session's VOLE correlation from it (Protocol 5.2 steps 2-3). No VOLE state is
serialized in `SignerSetup`. Regression test: `TestSignSessionsUseFreshVOLE`.

### FU-HIGH-1: IKNP OT extension without consistency check — RESOLVED

**File**: `ot_extension.go`
**Severity**: High
**Category**: Selective-failure attack / key recovery

The extension was plain IKNP, which is only passively secure against the
receiver. A malicious Bob can send inconsistent correction rows and learn
Alice's base-OT choice bits σ through selective abort; with σ he obtains both
OT messages and reads Alice's nonce and key share from her multiply message.

**Resolution**: KOS15 (Figure 7) consistency check made one-message by
deriving the challenge with Fiat-Shamir from the correction matrix, with the
statistical parameter replaced by λc, exactly as prescribed in DKLS23 §5.1.
The batch is padded with 2λc sacrificial OTs (ℓ' = ξ + 2λc), the check runs
in constant-time GF(2^128) arithmetic (`gf128.go`), and a failing check
aborts the FRVOLE instance and blacklists the sender (Protocol 3.6 step 8).

### FU-MED-1: DKG revealed Feldman commitments before commitment — RESOLVED

**File**: `dkg.go`
**Severity**: Medium
**Category**: Protocol deviation (public-key bias)

Protocol 7.1 step 2 has each party *commit* via FCom to its Feldman
commitments and to each pairwise share, and only release them in step 3 once
all commitments are known. The implementation broadcast the Feldman points in
round 1, letting a rushing last party choose its polynomial after seeing the
others' and bias the group key.

**Resolution**: `DKGRound1Output` now carries only FCom commitments;
`DKGRound2` requires every other party's round 1 commitment before releasing
the Feldman vector, its salt, the shares and their salts; `DKGFinalize` opens
both commitments before the Feldman check.

### FU-MED-2: Feldman commitment count not validated — RESOLVED

**File**: `dkg.go`, `refresh.go`
**Severity**: Medium
**Category**: Input validation (liveness)

A party could commit to a polynomial of the wrong degree; the resulting key
would not be reconstructible by any t parties. **Resolution**: exactly t
commitments (t−1 for refresh) are required; share encodings that overflow the
group order are rejected.

### FU-MED-3: FROST DKG had no proof of knowledge — RESOLVED

**File**: `frost/keygen.go`, `frost/hash.go`
**Severity**: Medium
**Category**: Protocol deviation (rogue-key / public-key bias)

The DKG was plain Pedersen DKG. The FROST paper (Figure 1) requires each
participant to prove knowledge of its constant term a_i0 with a Schnorr
proof σ_i = (R_i, μ_i), c_i = H(i, Φ, φ_i0, R_i), verified by every other
participant before round-2 shares are sent, "to protect against rogue key
attacks".

**Resolution**: `DKGRound1Output` now carries `ProofR`/`ProofMu`;
`DKGPartyConfig.Context` supplies Φ; `DKGRound2` takes all round-1 outputs
and verifies every proof before releasing shares, and `DKGFinalize` verifies
them again. The proof hash is this package's instantiation of the paper's H
(`SHA-512(ContextString || "dkg" || id || Φ || φ_i0 || R_i) mod L`), since
RFC 9591 specifies no DKG. The nonce k is zeroized.

### FU-MED-4: FROST element decoding and conformance not verified — RESOLVED

**File**: `frost/sign.go`, `frost/keygen.go`, `frost/verify.go`,
`frost/vectors_test.go`
**Severity**: Medium
**Category**: Specification conformance

Received group elements were decoded with `edwards25519.Point.SetBytes`,
which accepts non-canonical encodings and does not reject the identity or
elements outside the prime-order subgroup, contrary to RFC 9591 §6.1
`DeserializeElement`; the earlier audit nevertheless claimed non-canonical
point rejection. No RFC test vectors were run.

**Resolution**: `deserializeElement` implements §6.1 (RFC 8032 decoding,
canonical re-encoding check, identity and small-order rejection) and is used
for every received element (Feldman commitments, nonce commitments,
verification shares, group public key, proof R). `frost/vectors_test.go`
runs the RFC 9591 Appendix E.1 FROST(Ed25519, SHA-512) vectors through the
implementation: nonce generation, commitments, binding-factor inputs and
factors, both signature shares and the final signature all match exactly,
and the signature is accepted by `crypto/ed25519.Verify`. The cofactored
verification equation is pinned by a test using an order-8 component.

### FU-LOW-1: `SignCounter` did not guard anything — RESOLVED

The counter was incremented but never checked, contrary to its
documentation. It is removed; with FU-CRIT-1 resolved there is no stored
session material to protect from rollback.

### FU-LOW-2: `SignCombine` double-counted the caller's fragment — RESOLVED

Passing `SignRound3`'s full output map (which includes the caller's own
entry) together with the explicit own-fragment arguments produced an invalid
signature. The own entry is now ignored.

### FU-LOW-3: No wire-format version — RESOLVED

`SignerSetup` JSON now carries `"version": 1`; unknown or missing versions
are rejected on deserialization.

### FU-LOW-5: FROST wire format unversioned; blacklisting advice overstated — RESOLVED

`KeyShare` and `SignerState` JSON now carry `"version": 1` and reject
missing or unknown versions. The documentation of `Aggregate`,
`SignerState.Blacklist` and `CheatingPartyError` now states, with the RFC
9591 §5.4 and §7 text, that identifiable abort assumes an authenticated
channel and a non-equivocating Coordinator: a Coordinator that hands signers
different commitment lists makes an honest signer's share fail verification,
so automatic permanent blacklisting is only safe with an honest or
reliable-broadcast Coordinator.

### FU-LOW-6: Session-id freshness was a caller obligation only — RESOLVED

**File**: `sign.go`, `refresh.go`, `encoding.go`
**Severity**: Low (as shipped: documented requirement; High if violated)
**Category**: Defense in depth

Protocol 3.6 step 4 has a party ignore a signing request whose `sigid` is not
fresh. The library documented this for callers but did not check it. The
OT-extension rows are a PRF of the base seeds and the session id, so a reused
id reproduces the session's OT correlation on every column whose choice bit
happens to repeat, and from such columns a counterparty reads the signer's
nonce difference directly, the same class of leak as FU-CRIT-1.

**Resolution**: `SignerSetup.SessionIDs` records the last completed round of
every session id in the current epoch and is persisted with the setup.
`SignRound1` rejects an id already used, `SignRound2` requires round 1 and
rejects a second round 2, and `SignRound3` requires round 2 and rejects a
second round 3, each with `SessionIDReusedError`; a failed round does not
spend the id. `RefreshFinalize` clears the record because the refreshed
base-OT and FZero seeds re-key everything a session id feeds into. The check
is a backstop: two setups restored from the same snapshot cannot see each
other's records, so callers must still generate unique ids.

The sections that follow this one are the original review's text, preserved
as a historical record. Where it describes mechanisms that the follow-up
review removed or replaced (for example the `SignCounter` field, the previous
base OT, or the claim that non-canonical points were rejected), the follow-up
entries above take precedence.

### FU-LOW-4: Base OT was not the specified protocol — RESOLVED

**File**: `ot.go`
**Severity**: Low
**Category**: Protocol deviation / documentation

The base OT was a Chou-Orlandi-style construction (receiver response
`R = bG + c·T`) documented as Masny-Rindal. DKLS23 §8.1 specifies the
two-round UC-secure endemic OT of Masny and Rindal instantiated from DDH
over the signing curve.

**Resolution**: `ot.go` now implements MR19 Figure 8 (1-out-of-2) with the
Diffie-Hellman key agreement of MR19 Appendix D.1: the receiver samples
`r_{1-c}` uniformly and sets `r_c = a·G − H_c(r_{1-c})`; the sender recovers
`m_{A,j} = r_j + H_j(r_{1-j})`, replies with `b_j·G` and derives
`s_{B,j} = b_j·m_{A,j}`; the receiver derives `s_{A,c} = a·m_{B,c}`. Output
seeds are derived from the agreed key through the random oracle (Remark D.4).
`H_j` is a hash-to-curve random oracle with unknown discrete log. All
choice-bit-dependent selections are constant-time byte copies on affine
coordinates; a message that would force an agreed key to the point at
infinity is rejected. The receiver now speaks first (two rounds), and the
receiver's key-agreement secrets are zeroized after finalization.

---

## 2026-10-21 Hardening Addendum

**Reviewer**: Codex (automated source review and regression construction).
**Scope**: nonce/state lifetime, secret curve operations and hash-output
reduction, refresh replay, and accuracy of security claims. No protocol
messages, hash transcripts, security parameters or proof equations changed.

### FU-HIGH-2: Concurrent FROST nonce consumption — FIX IMPLEMENTED

**Files**: `frost/sign.go`, `frost/session_test.go`
**Severity**: High
**Category**: One-use nonce state / data race
**Specification**: RFC 9591 §5.1–5.2: a nonce pair is used at most once and
deleted after signing.

`SignRound2` held a shared read lock while reading `consumed` and mutating
nonce scalars. A targeted race-enabled test submitted 16 concurrent calls
with one state: 10 returned success and the race detector reported conflicting
reads/writes. This establishes a broken one-use guard, not a demonstrated
private-key recovery attack from the race.

**Resolution**: round 2 holds the signer's write lock; copies of states
returned by round 1 share a consumption record with its own mutex. Matching
key, party, participant-set and epoch checks permit equivalent signer wrappers
without permitting concurrent consumption. Nonce/commitment consistency is checked, caller
participant lists and outbound commitments are independently copied, and
successful signing zeroizes nonce objects. Raw secret nonce material must
never be manually duplicated or reused. Regression tests require exactly one
successful share, including across restored wrappers, and verify the resulting
signature with `crypto/ed25519`.
The RFC Appendix E.1 vector test is unchanged.

**Tested**: `TestSignConcurrentNonceConsumption` requires exactly one success
and independently verifies the aggregate for original, copied, restored-wrapper
and raw-state cases. `TestSignCopiedNonceStateIsSingleUse` verifies the winning
share after a sequential retry. `TestSignRejectsChangedNonceAssociation` tests
different public keys and participant sets; the other signer/epoch and
restoration tests are mapped in SECURITY.md. These tests do not demonstrate
resistance to manually duplicated independent secret nonce material.

### FU-HIGH-3: Variable-time operations on DKLS23 secrets — FIX IMPLEMENTED

**Files**: `dkls23/curve.go`, `ot.go`, `dkg.go`, `sign.go`, `refresh.go`
**Severity**: High (side-channel risk; exploitability is deployment-dependent)
**Category**: Secret-dependent curve arithmetic and encoding
**Specification**: secp256k1 group operations of DKLS23 Protocols 3.6, 7.1,
and MR19 Figure 8 / Appendix D.1. These operations must preserve the same
group values and encodings; the cryptographic construction is unchanged.

Secret nonces, polynomial coefficients, masked shares and OT DH scalars were
passed to btcec `ScalarBaseMultNonConst` / `ScalarMultNonConst`. Having a
constant-time scalar representation did not make these point operations
constant-time. Point serialization and the surrounding point operations also
needed review, especially on secret DH points.

**Resolution**: use `github.com/bytemare/secp256k1` v0.5.0 for a fixed 256-bit
ladder, complete point addition and coordinate encoding. Secret-selected
finite points use constant-time byte copies of full coordinates, not a
secret-selected compressed-point decoder. btcec remains for scalar arithmetic
and independent public ECDSA verification. Differential tests cover both
point multiplication forms, zero, q-1, addition and cancellation. Received
points must use the existing 33-byte compressed SEC1 format.

**Assurance limit**: this is not a claim that the new backend or its compiled
integration has received an independent audit. No practical timing/cache
key-recovery exploit was demonstrated. Independent review and target-specific
side-channel analysis remain production gates.

**Tested**: `TestCurveOperationsMatchBTCEC` and
`TestPointDecodeRequiresCompressedSEC1` check arithmetic and accepted encodings.
`TestProductionAvoidsVariableTimeAPIs` parses both packages' production source
to reject `math/big` imports and calls named `NonConst`.
**Only read**: pinned backend multiplication, complete addition, coordinate
encoding and scalar conversion source, with references in `curve.go`. Neither
the differential tests nor the source-policy test measures compiled timing.

### FU-MED-5: FZero secret output treated as public — FIX IMPLEMENTED

**Files**: `dkls23/params.go`, `commitment.go`, `vole.go`, `reduction_test.go`
**Severity**: Medium
**Category**: Variable-time reduction of secret PRF outputs
**Specification**: DKLS23 §3.1 FZero and Protocol 5.2 Fiat-Shamir challenge
derivation, with the existing 64-byte SHAKE output reduced modulo q.

`reduce64Public` used `math/big` for FZero outputs derived from a private
pairwise seed. These values were incorrectly described as public. No
practical key-recovery attack from this reduction was demonstrated.

**Resolution**: reduce the exact same integer as
`high * (2^256 mod q) + low`, using constant-time `ModNScalar` operations and
the already computed `gadget[256]`. Both callers use a fixed 64-byte array;
FZero's output buffer is cleared. Differential tests against `big.Int` and
an independently encoded FZero transcript verify identical results, including
zero, all-ones and group-order boundaries. Production code no longer imports
`math/big`; reference calculations use it only in tests.

**Tested**: `TestReduce64MatchesBigInt` and
`TestFZeroMatchesReferenceReduction` check the exact reduction and PRF
transcript; `TestProductionAvoidsVariableTimeAPIs` checks the import policy.
**Only read**: timing properties of the dependency's scalar methods and the
explicit buffer clear. The tests establish arithmetic compatibility, not
compiled constant-time behavior or removal of memory copies.

### FU-MED-6: Persisted DKLS23 signing state lacks key/epoch association — OPEN

**Files**: `dkls23/sign.go`, `dkls23/encoding.go`
**Severity**: Medium
**Category**: Session-state association / stale private state
**Specification**: DKLS23 Protocol 3.6's local setup and `sigid` association.

The existing persisted round-state format does not carry a key or epoch
binding. A different setup can have the same session id and recorded stage,
or a refresh can permit that id under new seeds while old private state still
exists. The application must retain the correct association between private
round state, setup, participants and key epoch.

**Disposition**: existing session-id freshness and round-progress checks are
retained. This branch preserves the existing persisted formats and restoration
behavior; it does not add process-identity restrictions or redesign persistence.
The missing persisted association remains open and requires a separately
reviewed compatibility change. Regression tests finish signing after valid
setup and round-state restoration and independently verify the signatures.

**Tested**: `TestSignResumesWithRestoredSetup`,
`TestSignResumesWithRestoredRoundState` and `TestSignResumesAfterInPlaceRestore`
check valid restoration and independent ECDSA verification.
**Only read**: the missing key/epoch fields in the persisted schema. No test
establishes safe association of arbitrary stale or mismatched private state;
that remains a Known Limitation, not a resolved guarantee.

### FU-MED-7: Duplicate refresh finalization accepted — LOCAL REPLAY FIX IMPLEMENTED

**Files**: both packages' `refresh.go`, signer state, encoding and refresh
session tests
**Severity**: Medium
**Category**: Local refresh replay / key-state consistency
**Specification**: one application of the existing refresh polynomial and
auxiliary-state update per refresh instance; no modification to its equations.

A targeted reproduction in each package called `RefreshFinalize` twice with
the same local contribution and received messages. Both calls succeeded and
the epoch became 2. The epoch counter was bookkeeping, not an enforced
refresh replay guard. Repeated updates can desynchronize shares and auxiliary
state. This review did not establish full proactive security of refresh.

**Resolution**: after all validation and a successful update, finalization
records the completed local seed contribution, public key and party id under
the signer's write lock. The seed is already public in refresh round 2. A
repeat is rejected before mutation. No new protocol identifier, hash input,
message or equation is introduced, and round 1 does not retire pending work.
Concurrent and sequential replay tests require exactly one epoch increment;
an older completed contribution stays rejected after a subsequent refresh.
Independent signature verification checks the resulting group shares.
Compatibility tests also finish pending refresh after signer restoration.

**Integration limit**: the completion record is local and is not serialized.
It does not provide replay protection on a newly restored object or bind
peer messages to a fresh authenticated session. Applications must durably
track applied refreshes, route authenticated transcripts and coordinate
epoch activation. KMOS21 conformance, the corruption/erasure model and refresh
auxiliary-state security remain independent-review gates. Earlier claims that
an epoch counter alone prevents replay are superseded by this entry.

**Tested**: each package's `TestRefreshFinalizeIsSingleUse` races eight calls,
requires one successful epoch increment, retries sequentially, verifies a
signature independently and rejects an older contribution after another
refresh. `TestRefreshPreservesPendingContribution` and
`TestRejectedImportPreservesPendingRefresh` exercise restoration and failed
imports. **Only read**: the local completion record's omission from JSON.
The tests do not establish durable replay protection or proactive security.

### FU-MED-8: Rejected private-state imports modify active sessions — FIX IMPLEMENTED

**Files**: both packages' `encoding.go`, signing and refresh session tests
**Severity**: Medium
**Category**: Partial state replacement / failed-import side effects
**Requirement**: rejected deserialization must leave the destination unchanged
(CLAUDE.md, Testing). This is an implementation property, not a new protocol
message, equation or transcript input.

Existing DKLS23 setup and round-state decoders published fields before
validating later fields, and the FROST signer decoder replaced the key share
before validating blacklist keys. A rejected import could leave mixed state
or discard a live operation.

**Resolution**: decode and validate into temporary values, then publish only
after success. Signer replacement retains the receiver's mutex and acquires
its write lock for publication. DKLS23 round 1 and round 2 replacements are
also published only after complete decoding. Tests reject unsupported
versions, malformed early and late fields, verify unchanged serialized state,
and complete the original operation with independent signature verification.
Additional tests finish pending refresh after a rejected import and verify a
signature under the refreshed shares. Persisted field layouts and valid
restoration behavior are unchanged.

**Tested**: each package's `TestRejectedImportPreservesSigningSession` compares
serialized state before and after rejected inputs and completes signing with
an independent verifier. `TestRejectedImportPreservesPendingRefresh` does the
same for pending refresh. This entry originally covered signer and DKLS23
private round-state decoders; FU-MED-9 covers the remaining custom decoders.

### FU-MED-9: Other custom JSON decoders mutate receivers on rejection — FIX IMPLEMENTED

**Files**: both packages' `encoding.go`, `dkls23/setup_messages.go`, both
`unmarshal_errors_test.go` files
**Severity**: Medium
**Category**: Failed-import side effects / state integrity
**Requirement**: CLAUDE.md rule 11 requires a receiver-preservation test for
every custom `UnmarshalJSON`; this is an API-state property, not a protocol
construction or wire-format change.

The claim-evidence review extended FU-MED-8's rejection tests to every custom
decoder. These tests failed on the existing DKG messages, OT seed states,
VOLE states/messages, signing messages, refresh messages, FZero messages and
FROST key-share/nonce/signature decoders: a malformed field could overwrite
that field or publish earlier fields before an error was returned.

**Resolution**: decode through a temporary receiver and publish only on success.
These types have no mutex; signer decoders continue to retain and lock their
existing mutexes. Temporary copies preserve existing successful decoding
behavior, including fixed-array copy behavior. No new input restrictions,
wire fields, versions, hash inputs or protocol checks were introduced.

**Tested**: `TestRejectedUnmarshalPreservesReceiver` in each package corrupts
fields of populated receivers and requires byte-identical serialized state
after rejection. The tests failed before this fix and pass after it. Existing
round-trip and restoration tests check successful imports. The already
transactional OT-extension decoder is included in the rejection tests.
**Only read**: the full set of decoder error paths for publication order.
This does not assert complete semantic validation of a successfully decoded
transcript; receiving rounds still perform protocol checks. The two base-OT
message types use standard `encoding/json`, whose error behavior is outside
the custom-decoder guarantee; callers must discard rejected messages.

### FU-LOW-7: Security claims exceeded their regression evidence — CORRECTED

**Files**: `SECURITY.md`, README files, `CLAUDE.md`, GoDoc and fuzz/error tests
**Severity**: Low
**Category**: Assurance and test-coverage claims

The existing security document claimed strict subgroup/identity validation
for every received group element, while FROST public signature verification
intentionally uses RFC 8032 decoding and the cofactored equation required by
RFC 9591 §6.1. It also described blacklists as permanent across all future
sessions and fuzz/error coverage as universal. Four FROST key-share error
cases and the blacklist-key case omitted the required version, so those
tests rejected the version before reaching their named field.

**Resolution**: distinguish strict protocol element decoding from signature
verification, scope blacklist enforcement to retained state, and map the
remaining implementation claims to named tests in SECURITY.md. Move untested
timing, complete erasure, RNG-failure resistance and semantic-decoder
assumptions to Known Limitations. Preserve the verifier and protected vectors.

**Tested**: repaired malformed-field cases include valid versions and assert
field-specific errors. Named fuzz targets now cover every custom decoder and
both base-OT messages; valid-version FROST seeds reach field decoding.
`TestSignSessionRoundsAreSingleUseConcurrent` races all three DKLS23 signing
rounds, requires exactly one success, rejects an immediate sequential replay
of each round and independently verifies the resulting ECDSA signature.
The FROST cofactored-verification and invalid-element tests falsify the
previous overly broad validation claim. The implementation-behavior tables
in SECURITY.md identify the other existing positive and negative tests.

The DKG cheating test stopped at the hash opening, and refresh Feldman tests
could stop at point decoding. The new FROST
`TestDKGRejectsShareInconsistentWithCommitments` recomputes the forged share's
hash commitment, requires valid point decoding, rejects exactly the offending
party and independently verifies a signature by unaffected recipients.
Both packages' `TestRefreshBadFeldman` now use different valid points and
require typed attribution, reaching the Feldman equation rather than relying
on an earlier decoding error.
`TestRefreshFZeroSeedsChangeAndMatchPeers` checks that every DKLS23 FZero
pairwise seed changes, agrees across peers, and still permits independent
signature verification; base-OT correlation tests alone do not test this.

**Only read**: RFC 9591 §6.1 and dependency sources cited in GoDoc, including
scalar arithmetic, point multiplication/addition/encoding and explicit
clears. No new compiled timing, cache-side-channel or memory-erasure
experiment was performed. Historical "resolved" and "verified" labels above
and below record earlier reviews; they do not supply missing evidence for
the broader security claims. The current SECURITY.md evidence and Known
Limitations take precedence over such historical assurances.

---

## Findings

### HIGH-1: Secret-dependent branching in BaseReceiverRound1 — RESOLVED

**File**: `ot.go:146-155`
**Severity**: High
**Category**: Timing side channel

The base OT receiver branched on the secret choice bit `choices[k]`,
performing a scalar multiplication + point addition in the `true` path
but only a struct assignment in the `false` path.

**Resolution**: Replaced with branchless multiply-by-mask pattern using
`condUint32(choices[k])` as the scalar. The point addition is always
executed; when the choice is false the scalar is 0, producing the identity
point, which adds to bG as a no-op.

---

### MED-1: Non-atomic VOLE state mutation during refresh — RESOLVED

**File**: `refresh.go:276-295`
**Severity**: Medium
**Category**: State consistency

VOLE states were re-randomized in-place during `RefreshFinalize`. If
`refreshVOLEAlice` succeeded for one peer but `refreshVOLEBob` failed for
another, the setup was left in a partially-mutated state.

**Resolution**: `refreshVOLEAlice` and `refreshVOLEBob` now return new
state objects instead of mutating in place. All new states are built into
temporary maps and swapped into `setup` only after every peer succeeds.

---

### MED-2: Missing nil guard on VOLE Bob state in SignRound3 — RESOLVED

**File**: `sign.go:440`
**Severity**: Medium
**Category**: Denial of service

`state2.VoleBobForRound2[j]` was accessed without a nil check. A nil
pointer dereference would crash the process if pairwise VOLE setup was
incomplete.

**Resolution**: Added `if bobState == nil` guard that appends to
`badParties`, blacklists, and continues.

---

### MED-3: Missing zeroization of intermediate share bytes — RESOLVED

**File**: `dkg.go:149-153`, `dkg.go:182-186`, `refresh.go:106-111`, `refresh.go:158-162`
**Severity**: Medium
**Category**: Memory exposure

When computing pairwise commitments, the share scalar was serialized to a
`[32]byte` for FCom but the byte array was not zeroized after use.

**Resolution**: Added explicit zeroing of `shareArr` after each `Commit`
call and after each `copy` in DKGRound1, DKGRound2, RefreshRound1, and
RefreshRound2.

---

### MED-4: Lagrange coefficient not defer-zeroized — RESOLVED

**File**: `sign.go:278-282`
**Severity**: Medium
**Category**: Memory exposure

The Lagrange coefficient `lc` was zeroed after use but not via `defer`,
meaning a future refactoring could introduce an early return that skips
zeroization.

**Resolution**: Changed `lc.Zero()` to `defer lc.Zero()` immediately
after creation.

---

### LOW-1: DKG input validation gaps — RESOLVED

**File**: `dkg.go:102-117`
**Severity**: Low
**Category**: Input validation

`DKGRound1` did not check for duplicate party IDs, non-positive IDs, or
IDs exceeding the uint32 range used by `ModNScalar.SetInt`.

**Resolution**: Added `validatePartyIDs` helper that checks all IDs are
in `[1, 2^31)` with no duplicates. Called at the top of `DKGRound1` and
`SignRound1`.

---

### LOW-2: Domain separation strings not centrally managed — RESOLVED

**File**: Multiple (`ot.go`, `ot_extension.go`, `vole.go`, `commitment.go`, `refresh.go`)
**Severity**: Low
**Category**: Protocol design

Domain separation strings were hardcoded across 6 files with no
compile-time mechanism to prevent collisions.

**Resolution**: All 9 domain strings are now named constants in `params.go`
(`domainBaseOT`, `domainOTEPRG`, `domainOTESeed`, `domainOTEExpand`,
`domainVOLEFS`, `domainVOLEProof`, `domainVOLERefresh`, `domainFZero`,
`domainFZeroRefresh`). All call sites reference the constants.

---

### LOW-3: reduce64 callable on secret data without guard — RESOLVED

**File**: `params.go:97-104`
**Severity**: Low
**Category**: API misuse risk

`reduce64` used non-constant-time `math/big` reduction. The function was
documented as public-data-only but nothing enforced this.

**Resolution**: Renamed to `reduce64Public` to make the contract explicit
at every call site.

---

### LOW-4: Nonce reuse risk on state snapshot rollback — RESOLVED

**File**: `sign.go`
**Severity**: Low
**Category**: Operational risk

If `SignerSetup` was restored from a backup after signing had occurred,
one-time VOLE correlations could be reused.

**Resolution**: Added `SignCounter uint64` to `SignerSetup`, atomically
incremented on each `SignRound1` call and persisted in JSON. A restored
setup's counter reveals how many signing sessions have consumed VOLE state.

---

### LOW-5: No bounds check on party IDs before uint32 cast — RESOLVED

**File**: `dkg.go:23`, `dkg.go:84`, `refresh.go:355`
**Severity**: Low
**Category**: Integer overflow

Party IDs were cast to `uint32` without bounds checking.

**Resolution**: Resolved together with LOW-1 via `validatePartyIDs`, which
rejects IDs outside `[1, 2^31)`.

---

---

## frost Findings

### FROST-MED-1: Secret key material left in nonceGenerate heap buffer — RESOLVED

**File**: `frost/sign.go:176-184`
**Severity**: Medium
**Category**: Memory exposure

`nonceGenerate` built an `input` slice containing `randomBytes || secret`
(the plaintext secret share). After computing `H3(input)`, neither
`randomBytes` nor `input` were zeroized, leaving key material in heap
memory until the GC reclaims it.

**Resolution**: Added explicit zeroing of both `randomBytes` and `input`
immediately after the `H3` call returns.

---

### FROST-MED-2: Panic on malformed nonce commitment in computeGroupCommitment — RESOLVED

**File**: `frost/sign.go:366-387`
**Severity**: Medium
**Category**: Denial of service

`computeGroupCommitment` called `panic()` if a nonce commitment point
failed to parse. A malicious party sending garbage commitment bytes would
crash the entire process rather than producing an identifiable error.

**Resolution**: Changed `computeGroupCommitment` to return `(*Point, error)`
instead of `*Point`. Both callers (`SignRound2`, `Aggregate`) now propagate
the error as an `InvalidInputError`.

---

### FROST-LOW-1: Missing Feldman commitment count validation — RESOLVED

**File**: `frost/keygen.go:282-380`
**Severity**: Low
**Category**: Input validation

`DKGFinalize` did not verify that the number of Feldman commitments
received from each party matched the configured threshold `t`. A
malicious party could send fewer commitments, causing `feldmanVerify`
to silently verify against a lower-degree polynomial.

**Resolution**: Added `len(r1j.FeldmanCommitments) != config.Threshold`
check before share verification; mismatches are added to `badSenders`.

---

### FROST-LOW-2: Misleading sampleScalar comment — RESOLVED

**File**: `frost/keygen.go:108`
**Severity**: Low
**Category**: Documentation

`sampleScalar` was documented as sampling a "non-zero" scalar but did
not enforce this. The probability of zero is ~2^{-252} (negligible), but
the comment was misleading.

**Resolution**: Updated comment to accurately state the negligible
probability of sampling zero.

---

## frost Items Verified (No Issues Found)

| Area | Assessment |
|---|---|
| **Scalar arithmetic** | All secret scalar operations use `filippo.io/edwards25519` constant-time `Scalar` methods. No `math/big` on secrets. |
| **Nonce generation** | `nonceGenerate` implements RFC 9591's `nonce_generate`: `H3(random_bytes(32) \|\| secret)`. Hedged against bad RNG by mixing in the secret key. |
| **Nonce reuse prevention** | `Round1State.consumed` flag prevents second use. Nonces are zeroized to zero scalar after `SignRound2` computation. |
| **Hash functions H1-H5** | Correct RFC 9591 Section 6.5 instantiation. H2 has no domain prefix (RFC 8032 compatibility). H1/H3 use `ContextString \|\| tag`. All hash-to-scalar uses `SetUniformBytes` (64-byte wide reduction). |
| **Binding factor computation** | Matches RFC 9591 Section 4.3: `H1(group_pk \|\| H4(msg) \|\| H5(encoded_commitments) \|\| id)`. Commitment list encoded in ascending signer ID order. |
| **Cofactored verification** | `Verify` implements `[8]zB == [8](R + [c]PK)` per RFC 9591 Section 6.5. Clears small-subgroup component. |
| **RFC 8032 compatibility** | FROST signatures verify with `crypto/ed25519.Verify` (tested in `TestSignatureRFC8032Compatible`). |
| **Signature share verification** | `verifySignatureShare` checks `z_i*B == D_i + rho_i*E_i + c*lambda_i*PK_i` (RFC 9591 Section 5.4). Enables identifiable abort. |
| **Feldman VSS** | Standard Feldman verification: `s_i*B == sum(A_k * i^k)`. Commitment opening uses `subtle.ConstantTimeCompare`. |
| **Lagrange interpolation** | Constant-time via `edwards25519.Scalar`. Inversion via Fermat's little theorem (`a^{L-2} mod L`), fixed public exponent. |
| **Concurrency** | `SignerState.mu` RWMutex: RLock for SignRound1/2, no Lock needed (no VOLE state mutation). |
| **Commitment list ordering** | Deterministic: `sort.Ints(signersSorted)` before encoding. All parties compute identical binding factors. |
| **Serialization** | JSON encoding uses hex for scalars and points. Deserialization errors propagated. No secret data in error messages. |
| **Persistence** | `SetupEncryptor` interface separates encryption from serialization (same pattern as dkls23). |
| **Domain separation** | 4 domain tags (`rho`, `nonce`, `msg`, `com`) are named constants in `hash.go`. `ContextString` prefix prevents cross-ciphersuite collisions. |
| **`orderMinus2` constant** | Verified: L = `0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED`, L-2 has last byte `0xEB`. Little-endian encoding matches. |
| **Key refresh** | Zero-constant polynomial Feldman VSS. `RefreshFinalize` validates commitment count, FCom decommitment, Feldman consistency, and seed decommitment before mutating state. Verification shares updated atomically. Epoch counter incremented. |
| **Defense-in-depth** | `Aggregate` verifies the final signature against the group public key before returning, catching protocol bugs. |
| **Error messages** | All 9 frost production files reviewed. No secret scalar values, key material, or private state in any error string. |

---

## dkls23 Items Verified (No Issues Found)

| Area | Assessment |
|---|---|
| **Nonce generation** | `sampleScalar` uses `crypto/rand` with rejection sampling. Bias from 256-bit reduction mod q is < 2^-128 (negligible). |
| **Scalar arithmetic** | All secret operations use constant-time `ModNScalar`. No `math/big` on secrets. |
| **VOLE Beta selection** | All Beta-dependent paths use branchless multiply-by-mask or `subtle.ConstantTimeCopy`. |
| **OT extension Beta** | `oteSeedHash` and `oteExpandHash` write the choice bit branchlessly via `condUint32`. |
| **Commitment scheme** | FCom uses SHA-256(msg ‖ salt) with 32-byte random salt. Opening is constant-time via `subtle.ConstantTimeCompare`. |
| **Low-S normalization** | Uses `ModNScalar.IsOverHalfOrder()` (constant-time) and `Negate()`. Correct per BIP-340. |
| **Signature verification** | `SignCombine` verifies the final (r, s) against the master public key before returning. Defense-in-depth against protocol bugs. |
| **Concurrency** | `SignerSetup.mu` RWMutex usage is correct: RLock for reads (SignRound1/2), Lock for writes (SignRound3, RefreshFinalize). `SignCounter` uses `atomic.AddUint64` (safe under RLock). No deadlock risk. |
| **Serialization** | JSON encoding uses fixed-size hex (scalars) and base64 (VOLE arrays). Wire format is backward-compatible. Deserialization errors are propagated. |
| **Persistence** | `SetupEncryptor` interface cleanly separates encryption from serialization. No key material in plaintext JSON after `MarshalEncrypted`. |
| **Cheating detection** | VOLE proof, FCom decommitment, Feldman verification, and public key consistency checks all implemented per the paper. Detected cheaters are blacklisted atomically. |
| **Proactive refresh** | KMOS21 Beaver OT re-randomization correctly maintains the OT correlation invariant. FZero seeds are re-derived from the combined seed. Epoch counter prevents replay. |
| **Domain separation** | All 9 domain tags are unique named constants in `params.go`. No collision risk. |

---

## Extended Verification

The following additional checks were performed beyond the initial code
review.

### Compiler Output Verification

`condUint32` (the branchless bool-to-uint32 helper used across all
Beta-dependent code paths) was disassembled on ARM64 (Apple Silicon).
The compiler emits a single `UBFX` (Unsigned Bit Field Extract) instruction
— no branch, no conditional move. This is the optimal codegen.

### Escape Analysis

`go build -gcflags='-m -m'` confirms that individual secret `ModNScalar`
values (`lc`, `sk_i`, `r_i`, `phi_i`, VOLE `dDot` array) remain stack-
allocated. Only dynamic-sized collections (`make(map)`, `make([]...)`)
escape to heap, which is expected. No secret scalar is unnecessarily
heap-allocated.

### `InverseValNonConst` Verification — REPLACED

Inspection of the decred/secp256k1 v4.0.1 source confirmed that
`InverseValNonConst` uses `big.Int.ModInverse` internally and is **not**
constant-time. The `decred/secp256k1` v4.0.1 is pinned by `btcec/v2` and
cannot be upgraded independently.

**Resolution**: Both call sites were replaced with `scalarInverse`, a
constant-time Fermat's little theorem implementation (`a^(q-2) mod q`)
using only `ModNScalar.Square` and `ModNScalar.Mul`. The exponent `q-2`
is a fixed public constant, so the square-and-multiply branch pattern is
data-independent. `InverseValNonConst` is no longer called anywhere in the
codebase.

### Error Message Review

All error messages across 19 production files (11 in dkls23, 8 in frost)
were reviewed. No secret scalar values, key material, or private state
appears in any error string. Only phase names, party IDs, and structural
descriptions are included.

### Protocol Equation Verification

Equation-by-equation comparison against the DKLS23 paper:

| Component | Paper Reference | Status | Deviations |
|---|---|---|---|
| DKG (Feldman VSS) | Protocol 7.1 | Correct | FCom for share exchange (standard hardening) |
| VOLE | Protocol 5.2 | Correct | None |
| Signing | Protocol 3.6 | Correct | SHA-256 for message hashing (standard for secp256k1) |
| FZero | Section 3.1 | Correct | Seed exchange via FCom |
| FCom | Section 3.1 | Correct | SHA-256 instantiation |
| Refresh | KMOS21 | Correct | Epoch counter (operational bookkeeping) |

No bugs or missing steps found. All deviations are standard instantiation
choices or correct engineering hardening.

### frost Protocol Equation Verification

Step-by-step comparison against RFC 9591:

| Component | RFC Section | Status | Deviations |
|---|---|---|---|
| DKG (Feldman VSS) | Appendix C (adapted to distributed) | Correct | 2-round distributed DKG instead of trusted dealer |
| Hash H1 (binding factor) | Section 6.5 | Correct | `SHA-512(ContextString \|\| "rho" \|\| m) mod L` |
| Hash H2 (challenge) | Section 6.5 | Correct | `SHA-512(m) mod L` — no domain prefix for RFC 8032 compatibility |
| Hash H3 (nonce) | Section 6.5 | Correct | `SHA-512(ContextString \|\| "nonce" \|\| m) mod L` |
| Hash H4 (message) | Section 6.5 | Correct | `SHA-512(ContextString \|\| "msg" \|\| m)` |
| Hash H5 (commitment) | Section 6.5 | Correct | `SHA-512(ContextString \|\| "com" \|\| m)` |
| `nonce_generate` | Section 5.2 | Correct | `H3(random_bytes(32) \|\| secret)` |
| Binding factor | Section 4.3 | Correct | `H1(group_pk \|\| H4(msg) \|\| H5(encoded_commitments) \|\| id)` |
| Group commitment | Section 5.2 | Correct | `R = sum(D_i + rho_i * E_i)` |
| Signature share | Section 5.2 | Correct | `z_i = d_i + rho_i * e_i + lambda_i * s_i * c` |
| Aggregation | Section 5.3 | Correct | `z = sum(z_i)`, signature = `(R, z)` |
| Share verification | Section 5.4 | Correct | `z_i * B == D_i + rho_i * E_i + c * lambda_i * PK_i` |
| Verification | Section 6.5 | Correct | `[8]zB == [8](R + [c]PK)` (cofactored) |

No bugs or missing steps found. The only deviation is using a 2-round
distributed DKG instead of the RFC's trusted-dealer keygen.

### Fuzz Testing

**dkls23**: 12 fuzz targets in `dkls23/fuzz_test.go`:
- All `UnmarshalJSON` methods (8 targets)
- `hexToScalar` parser
- `feldmanVerify` with adversarial commitments
- `GadgetInnerProduct` with random beta vectors
- `validatePartyIDs` with boundary inputs

**frost**: 11 fuzz targets in `frost/fuzz_test.go`:
- All `UnmarshalJSON` methods (7 targets: KeyShare, SignerState, DKGRound1/2Output, NonceCommitment, SignatureShare, Signature)
- `feldmanVerify` with adversarial commitments
- `validatePartyIDs` with boundary inputs
- `H1` with arbitrary data
- `Verify` with garbage inputs (public key, R, z, message)

Initial fuzzing (10s per target) found no panics in either package.

### Unmarshal Error Testing

**dkls23**: 48 structured error cases across 15 test functions in `dkls23/unmarshal_errors_test.go`.

**frost**: 20 structured error cases across 8 test functions in `frost/unmarshal_errors_test.go`, covering all 7 serializable types with bad hex, invalid keys, truncated data, and non-canonical encodings.

### Edge-Case Testing

**dkls23**: 10 edge-case tests:
- 2-of-3 threshold signing, 2-of-2 minimal threshold
- Duplicate party IDs, negative IDs, zero IDs
- Nil VOLE Bob state (found and fixed a panic in SignRound2)
- SignCounter increment verification
- `validatePartyIDs` boundary cases

**frost**: 14 edge-case tests across topical test files:
- 2-of-2 minimal threshold DKG + signing
- Wrong Feldman commitment count, truncated shares, non-canonical scalars
- Corrupted nonce commitment points (off-curve y-coordinate)
- Missing signature shares, invalid share scalars
- Nonce reuse prevention, below-threshold rejection, invalid party IDs
- Post-persistence functional signing (marshal → unmarshal → sign → verify)
- Corrupted R/Z, wrong message, wrong public key in verification

### Vulnerability Scanning

`govulncheck` reports 0 vulnerabilities affecting this code. 9 findings
in stdlib modules (`crypto/tls`, `crypto/x509`, `html/template`, `net/url`,
`archive/zip`, `os`) are in packages not called by this library.

### Dependency Versions

| Dependency | Version | Used by | Status |
|---|---|---|---|
| `btcsuite/btcd/btcec/v2` | v2.5.0 | dkls23 | Current as of 2026-10-21 |
| `decred/dcrd/dcrec/secp256k1/v4` | v4.4.1 | dkls23 (indirect; holds the constant-time scalar and field code) | Raised explicitly above btcec's minimum (v4.4.0) |
| `filippo.io/edwards25519` | v1.2.0 | frost | Latest |
| `golang.org/x/crypto` | v0.58.0 | dkls23 | Current as of 2026-10-21; requires Go 1.26 |
| `stretchr/testify` | v1.12.1 | both (test only) | Current as of 2026-10-21 |

---

## Remaining Inherent Limitations

These are not code defects — they are inherent to the protocols, the Go
runtime, or the deployment environment:

| Limitation | Applies to | Reason |
|---|---|---|
| **Memory retention** | both | Go's GC may retain stack copies after zeroization. No `mlock` — would require platform-specific code and a C dependency. |
| **Random oracle model** | dkls23 | SHAKE-256 modeled as a random oracle is a cryptographic assumption from the DKLS23 paper. |
| **Random oracle model** | frost | SHA-512 modeled as a random oracle is a cryptographic assumption from FROST / RFC 9591. |
| **Physical side channels** | both | Power analysis, EM emanation require hardware countermeasures. |
| **`InverseValNonConst`** | dkls23 | Replaced with constant-time `scalarInverse` (Fermat's little theorem). No longer called. |
| **`randRead` test hook** | frost | **Removed.** Previously `var randRead` in `sign.go` enabled test injection but was mutable at runtime. Replaced with direct `crypto/rand.Read` calls. |
| **No independent audit** | both | This automated review is not a substitute for a third-party audit. |

---

## Severity Summary

### dkls23

| Severity | Found | Resolved |
|---|---|---|
| Critical | 0 | — |
| High | 1 | 1 |
| Medium | 4 | 4 |
| Low | 5 | 5 |
| **Total** | **10** | **10** |

### frost

| Severity | Found | Resolved |
|---|---|---|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 2 | 2 |
| Low | 2 | 2 |
| **Total** | **4** | **4** |

### Combined (original review)

| Severity | Found | Resolved |
|---|---|---|
| Critical | 0 | — |
| High | 1 | 1 |
| Medium | 6 | 6 |
| Low | 7 | 7 |
| **Total** | **14** | **14** |

### 2026-10-16 follow-up review

| Severity | Found | Resolved |
|---|---|---|
| Critical | 1 | 1 |
| High | 1 | 1 |
| Medium | 4 | 4 |
| Low | 6 | 6 |
| **Total** | **12** | **12** |

---

*This automated review is not a substitute for an independent third-party
security audit. A formal audit by a firm specializing in MPC protocols is
recommended before production deployment with real assets.*
