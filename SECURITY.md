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
- **VOLE consistency check**: Altered correlation values are rejected by
  the SHAKE-256 proof check. Timing of its comparison is discussed below.
- **R-commitment decommitment**: Parties commit to nonce shares in signing
  round 1 and decommit in round 2. Inconsistencies are detected and the
  cheating party is identified.
- **Blacklisting**: Signing rounds reject parties recorded in
  `SignerSetup.Blacklist`. The map is persisted with the setup. Callers must
  retain those entries and prevent rollback; exported maps can be changed by
  the application. This is not an irreversible ban across restored copies.

#### frost

Cheating detection in FROST is simpler due to Schnorr's linearity:

- **DKG proof of knowledge**: Each party proves knowledge of its polynomial's
  constant term with a Schnorr proof bound to a context string (FROST paper
  Figure 1); invalid proofs are rejected before shares are returned. Tests
  check the proof equation and reject altered proofs and context replay.
  They do not prove implementation-wide resistance to rogue-key attacks.
- **Feldman VSS verification**: Each party's DKG share is verified against
  broadcast Feldman commitments. Inconsistent shares are detected.
- **Element validation**: DKG, signing, aggregation and refresh protocol
  elements use RFC 9591 §6.1 `DeserializeElement` (canonical encoding,
  non-identity, prime-order subgroup). Public signature verification uses
  RFC 8032 decoding and the cofactored equation, as RFC 9591 §6.1 requires;
  it accepts some small-order components that protocol decoding rejects.
- **Signature share verification**: The aggregator can verify each individual
  signature share (`z_i * B == D_i + rho_i * E_i + c * lambda_i * PK_i`),
  enabling identifiable abort — the specific misbehaving signer is identified.
- **Blacklisting**: Callers can record excluded parties in
  `SignerState.Blacklist`, which signing checks and persistence retains.
  Per RFC 9591 §5.4 and §7, attribution assumes an
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

The following describes source choices and inspected dependency code, not
measured timing guarantees. The functional tests listed below check arithmetic,
encodings and protocol behavior. They do not test timing, cache behavior,
compiler transformations or deletion of memory copies. Those unestablished
properties are Known Limitations and independent-review production gates.

### dkls23

- **Scalar arithmetic**: Secret scalar operations use btcec's `ModNScalar`,
  whose dependency documents fixed-width constant-time arithmetic. Inversion
  uses Fermat's little theorem (`scalarInverse`: `a^(q-2) mod q` via square-and-multiply with
  fixed public exponent). Source references are in `scalarInverse`'s GoDoc.
- **Point arithmetic and encoding**: `github.com/bytemare/secp256k1` v0.5.0
  uses a fixed 256-bit multiplication ladder, complete point addition and
  SEC1 coordinate encoding with constant-time selections in the inspected
  source. References are in `curve.go`. The source-policy test rejects
  production calls named `NonConst` and imports of `math/big`; this checks
  neither dependency internals nor compiled timing. Final ECDSA verification
  uses public inputs and may use variable-time operations.
- **FZero reduction**: 64-byte PRF outputs are secret. Their reduction uses
  `ModNScalar` on both 256-bit halves and the existing `2^256 mod q` gadget
  entry. It computes exactly the former reduction without `math/big`.
- **VOLE Beta selection**: The source uses multiply-by-mask
  (`condUint32(β) * value`) and `subtle.ConstantTimeCopy` for selection.
  `condUint32` contains a Go conditional; its compiled behavior must be checked
  for each supported toolchain and target.
- **OT extension**: `gf128.go` uses fixed loops and masks for the KOS15
  consistency arithmetic. GF(2^128) known-answer and algebraic tests establish
  functional results, not constant-time execution.
- **Base OT**: the receiver's choice bits select between precomputed values
  with `subtle.ConstantTimeCopy`.
- **Commitment verification**: Source inspection found FCom opening and VOLE
  proof checks use
  `subtle.ConstantTimeCompare`.
- **Zeroization**: Tests check exposed DKG and base-OT state objects after
  their wipe methods. Clears of FZero output and curve-adapter byte buffers
  were inspected in source; their memory effects were not independently
  measured. See Memory retention under Known Limitations.

### frost

- **Scalar arithmetic**: Secret scalar operations use `filippo.io/edwards25519`
  `Scalar` methods (`Add`, `Multiply`, `Subtract`), which delegate to generated
  fiat-crypto code in the inspected v1.2.0 source. Modular
  inversion uses Fermat's little theorem
  (`scalarInverse`: `a^(L-2) mod L` via square-and-multiply with fixed public
  exponent). Source references are in `scalarInverse`'s GoDoc.
- **Nonce generation**: Hedged via RFC 9591's `nonce_generate`:
  `H3(random_bytes(32) || secret)`. Appendix E.1 vectors check this exact input
  and its output. Fresh CSPRNG output remains required; the formula does not
  make repeated or cloned random-generator state safe.
- **Commitment verification**: Source inspection found DKG share commitment
  checks use `subtle.ConstantTimeCompare`.
- **Zeroization**: Signing nonces (`HidingNonce`, `BindingNonce`) are zeroized
  to the zero scalar after `SignRound2` computation, as checked by the nonce
  consumption tests. The clear of `nonceGenerate`'s input buffer was inspected
  in source; no test establishes removal of its memory copies.
- **Nonce reuse prevention**: Round 2 holds the signer's write lock while
  checking and consuming nonce state (RFC 9591 §5.1–5.2). Copies of a state
  returned by `SignRound1` share one consumption record with its own mutex,
  including when used with equivalent signer wrappers. States returned by
  `SignRound1` check the matching key, participant set and epoch; local nonces
  must match the stored commitment. These checks do not make copied raw secret
  nonce material safe to reuse.

## Session Lifetime and Persistence

- Treat exported state fields as read-only during their lifetime. Do not
  copy mutex-bearing signer/setup objects or share their mutable fields
  between independent wrappers. The locks cover library calls, not direct
  field mutation by the application.
- A rejected custom `UnmarshalJSON` call leaves the receiver's serialized
  state unchanged. Decoding finishes before replacement; this does not imply
  full semantic validation of every field. Protocol rounds perform additional
  checks before using decoded messages.
  Regression tests finish the active signing or refresh operation after
  rejected imports and verify the resulting signatures independently.
- Signing and refresh check local configuration and key material before use.
  Signing rejects unconfigured participants; DKLS23 requires both base-OT
  directions and FZero material for every selected peer, while permitting
  absent setup for unselected peers. Later DKLS23 rounds check the stored
  nonce opening, FZero value, VOLE choice/scalar relation, masked share and
  required peer-map entries before evaluating peer messages. FROST checks
  canonical secret-share encoding and its verification share when provided;
  optional original DKG metadata is validated without treating it as a proof
  of the current refreshed share. These are local consistency checks, not
  authentication or proof of the original state association (FU-MED-10).
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
- The `session` package implements these rules over a caller-supplied
  transactional `Store`. Given a backend that satisfies the documented
  transaction and durability contract, `Advance` commits at most one result
  per operation and round, saving the updated key checkpoint, private round
  checkpoint, nonce marker, cached output and blacklist changes atomically
  before returning any bytes. It returns committed bytes again through
  `Output` after a lost acknowledgement, rejects requests carrying an older
  key revision, and blocks signing while a refresh
  is pending until `Activate`. The nonce-marker check also rejects a repeated
  nonce under another session or epoch, which is how cloned RNG state would
  surface. The guard cannot supply the backend's durability, authenticate
  peers, notice a store and signer restored together from one old snapshot,
  or agree on activation with the group. The repository ships only the
  in-memory test model, not a backend. A rolled-back attempt can be recomputed
  by a later explicit `Advance` call; `Compute` must decode fresh checkpoints,
  avoid external side effects and return output only through `Update`.
  `storetest.Run` checks rollback from empty and populated storage, retaining
  complete committed records and nonce reservations. Passing the finite
  suite does not establish every part of the contract or physical durability
  (FU-MED-11 and FU-MED-12).
- On refresh, quiesce old signing sessions, authenticate the refresh session,
  agree on success, and persist the new epoch consistently across the group.
  A local one-use guard cannot solve a partial distributed commit or recovery
  from old backups. Recovery must not silently activate mixed epochs.
- The examples demonstrate protocol calls and encryption, not a production
  storage or recovery system. Their colocated encryption keys and direct
  `os.WriteFile` calls do not meet these requirements, and they do not yet
  use the `session` package.

## Evidence and Test Coverage

CI measures statement coverage (required minimum: 90% per package), runs the
race detector, and runs every fuzz target for five seconds. A finite fuzz pass
does not establish rejection of all malformed inputs or absence of panics.

Every custom JSON decoder has a named unmarshal fuzz target in each package's
`fuzz_test.go`; DKLS23 also fuzzes its two base-OT message types that use the
standard JSON decoder. Receiver-preservation tests cover each custom decoder,
with separate live-session tests for signer and DKLS23 private round state.

Edge-case tests cover malicious inputs (corrupted commitments, inconsistent
OT-extension batches, forged DKG proofs, non-canonical scalars and points,
small-order points, truncated shares), nonce reuse prevention, independence
of VOLE messages across signing sessions, post-persistence functional
round-trips, and identifiable abort.
Additional tests exercise concurrent nonce consumption and refresh finalization,
copied and restored state, stale epochs, exact FZero reduction, and differential
curve operations. These are regression checks, not an independent audit.

The following maps implementation claims above to falsifying tests. A listed
test supports its asserted behavior on tested inputs, not the cited protocol's
full security theorem. Timing and erasure observations remain source review
only, as described under Known Limitations.

| DKLS23 behavior | Evidence |
| --- | --- |
| Threshold signing and independent ECDSA verification | `TestSign3of3`, `TestDKG2of3Sign2of3` in [sign_test.go](dkls23/sign_test.go) and [dkg_test.go](dkls23/dkg_test.go) |
| Per-session VOLE changes and persistent setup excludes VOLE state | `TestSignSessionsUseFreshVOLE` in [sign_test.go](dkls23/sign_test.go); `TestEncodingSignerSetupVersion` in [encoding_test.go](dkls23/encoding_test.go) |
| KOS15 corruption rejection and peer attribution | `TestOTExtensionMaliciousReceiverInconsistentRow`, `TestOTExtensionTamperEveryXBarBit` in [ot_extension_test.go](dkls23/ot_extension_test.go); `TestSignBadOTExtension` in [sign_test.go](dkls23/sign_test.go) |
| VOLE correlation equation, proof rejection and signing attribution | `TestVOLECorrectnessRandom`, `TestVOLEMaliciousATilde` in [vole_test.go](dkls23/vole_test.go); `TestSignBadVOLEMessage` in [sign_test.go](dkls23/sign_test.go) |
| Commitment rejection and blacklist enforcement | `TestSignBadRCommitment`, `TestSignBlacklistedPartyRejectedEverywhere` in [sign_test.go](dkls23/sign_test.go); `TestEncodingSignerSetupWithBlacklist` in [encoding_test.go](dkls23/encoding_test.go) |
| DKG commits before reveal and rejects inconsistent shares | `TestDKGRound1RevealsNothing`, `TestDKGRejectsPolynomialChangedAfterCommitment`, `TestDKGRejectsShareInconsistentWithCommitments` in [dkg_test.go](dkls23/dkg_test.go) |
| Point arithmetic agrees with an independent backend; compressed input checks | `TestCurveOperationsMatchBTCEC`, `TestPointDecodeRequiresCompressedSEC1` in [curve_test.go](dkls23/curve_test.go) |
| Exact FZero reduction and transcript | `TestReduce64MatchesBigInt`, `TestFZeroMatchesReferenceReduction` in [reduction_test.go](dkls23/reduction_test.go) |
| Scalar inverse result | `TestScalarInverseCorrectness`, `TestScalarInverseKnownValue` in [ot_test.go](dkls23/ot_test.go); these are arithmetic tests, not timing tests |
| FCom tampering and FZero zero-sum output | `TestCommitOpenTamperedMsg`, `TestCommitOpenTamperedSalt`, `TestFZeroThreePartiesSum` in [commitment_test.go](dkls23/commitment_test.go) |
| GF(2^128) arithmetic and both OT choice values | `TestGF128KnownAnswers` in [gf128_test.go](dkls23/gf128_test.go); `TestBaseOTBothChoiceValues` in [ot_test.go](dkls23/ot_test.go) |
| Source policy excluding `math/big` imports and `NonConst` calls in both packages | `TestProductionAvoidsVariableTimeAPIs` in [curve_test.go](dkls23/curve_test.go); this is not a timing test |
| Wiped DKG and base-OT state objects | `TestDKGPrivateStateZero` in [dkg_test.go](dkls23/dkg_test.go); `TestBaseOTReceiverStateZero` in [ot_test.go](dkls23/ot_test.go) |
| One successful output per signing round; session progress survives persistence | `TestSignSessionRoundsAreSingleUseConcurrent` in [session_test.go](dkls23/session_test.go), including a sequential replay after each round; `TestSignSessionIDsSurvivePersistence` in [sign_test.go](dkls23/sign_test.go) |

| FROST behavior | Evidence |
| --- | --- |
| Exact nonce derivation, commitments, binding factors, shares and aggregate | Unchanged `TestRFC9591VectorsEd25519` in [vectors_test.go](frost/vectors_test.go) |
| Threshold subsets and independent Ed25519 verification | `TestDKG2of3SubsetReconstruction` in [keygen_test.go](frost/keygen_test.go); `TestSignatureRFC8032Compatible` in [sign_test.go](frost/sign_test.go) |
| DKG proof equation, altered proofs and context replay | `TestDKGProofOfKnowledgeFormula`, `TestDKGProofWrongMu`, `TestDKGProofReplayUnderDifferentContext` in [keygen_test.go](frost/keygen_test.go) |
| DKG hash-commitment and Feldman inconsistency | `TestDKGCheatingDetection`, `TestDKGRejectsShareInconsistentWithCommitments` in [keygen_test.go](frost/keygen_test.go); the latter passes hash opening and point decoding before requiring rejection |
| Strict protocol element decoding at receiving rounds | `TestDeserializeElementRFC9591`, `TestSignRound2RejectsInvalidCommitmentElements`, `TestAggregateRejectsInvalidElements`, `TestDKGRejectsInvalidElements`, `TestRefreshRejectsInvalidElements` in [element_test.go](frost/element_test.go) |
| Public verification uses the cofactored equation and rejects noncanonical encodings | `TestVerifyCofactoredEquation`, `TestVerifyRejectsNonCanonicalEncodings`, `TestVerifyNonCanonicalScalar` in [verify_test.go](frost/verify_test.go) |
| Share attribution when verification shares are supplied; aggregation without them | `TestSignCheatingShareDetection`, `TestSignAggregateWithoutVerificationShares` in [sign_test.go](frost/sign_test.go) |
| Blacklist enforcement and persistence | `TestSignBlacklist` in [sign_test.go](frost/sign_test.go); `TestSignerStateRoundTrip` in [encoding_test.go](frost/encoding_test.go) |
| Scalar inverse result | `TestScalarInverse`, `TestScalarInverseLarger` in [params_test.go](frost/params_test.go); these do not measure timing |
| One-use nonces, scalar-object wipe and copied/restored signer wrappers | `TestSignConcurrentNonceConsumption`, `TestSignCopiedNonceStateIsSingleUse` in [session_test.go](frost/session_test.go); winning shares aggregate and verify independently |
| Key, participant and epoch association; independent ownership of outbound data | `TestSignRejectsChangedNonceAssociation`, `TestSignRejectsNonceStateFromAnotherSigner`, `TestSignRejectsNonceStateAfterRefresh`, `TestSignRound1OwnsParticipantAndCommitmentCopies` in [session_test.go](frost/session_test.go) |

| Shared state and refresh behavior | Evidence in each package |
| --- | --- |
| Refresh preserves the key and reconstructed secret while changing shares | `TestRefreshPreservesPublicKey`, `TestRefreshSharesChangedButSameSecret`, `TestRefreshSignAfterRefresh` in each `refresh_test.go` |
| Refreshed auxiliary material and verification shares | DKLS23 `TestRefreshBaseOTSeedsStayCorrelated`, `TestRefreshFZeroSeedsChangeAndMatchPeers`; FROST `TestRefreshVerificationShareUpdated` in each `refresh_test.go`; these do not establish proactive security |
| Commitment, seed and Feldman tampering during refresh | `TestRefreshBadFCom`, `TestRefreshBadSeedCommitment`, `TestRefreshBadFeldman` in each `refresh_test.go` |
| Local refresh finalization is applied once, including concurrent calls and older replay | `TestRefreshFinalizeIsSingleUse` in each `refresh_session_test.go`; subsequent signatures verify independently |
| Rejected custom decodes preserve the serialized receiver | `TestRejectedUnmarshalPreservesReceiver` in each `unmarshal_errors_test.go`; `TestRejectedImportPreservesSigningSession` in each `session_test.go` for signer and private round state |
| Rejected imports preserve pending refresh | `TestRejectedImportPreservesPendingRefresh` in each `refresh_session_test.go` |
| Existing restoration behavior | DKLS23 `TestSignResumesWithRestoredSetup`, `TestSignResumesWithRestoredRoundState`, `TestSignResumesAfterInPlaceRestore`; FROST `TestSignResumesWithRestoredSigner`, `TestSignResumesAfterInPlaceRestore`; both `TestRefreshPreservesPendingContribution` |
| Reject malformed local keys/configuration and unconfigured signers before output | DKLS23 `TestSignRound1RejectsInvalidSetupBeforeOutput`, `TestSigningRejectsMalformedRestoredSetup`; FROST `TestSignRound1RejectsInvalidKeyBeforeOutput`, `TestSignRound1RejectsInvalidConfiguredElements`, `TestSigningRejectsMalformedRestoredKey`; both `TestSignRound1RejectsUnconfiguredParticipant` in `validation_test.go` |
| Covered local consistency failures preserve session progress, nonces and blacklists | DKLS23 `TestSignRound2RejectsInconsistentPrivateState`, `TestSignRound3RejectsIncompletePrivateState`; FROST `TestSignRound2RejectsInconsistentRestoredKey`; repaired states finish independently verified signatures |
| Preserve valid subset setup, minimal FROST keys and refreshed signing material | DKLS23 `TestSigningAcceptsPairwiseSetupForSelectedSubset`, `TestSetupValidationAcceptsRefreshedSigningMaterial`; FROST `TestSigningAcceptsMinimalKeyConfiguration`, `TestKeyValidationAcceptsRefreshedShareWithOriginalCommitments` |
| Reject invalid local refresh material before output or mutation | DKLS23 `TestRefreshRejectsInvalidSetupBeforeOutputOrMutation`, FROST `TestRefreshRejectsInvalidKeyBeforeOutputOrMutation`, and both `TestRefreshRound2RejectsWrongLocalPolynomialSize` |
| Session guard: at most one committed result per round across connections; rolled-back attempts can be recomputed without releasing uncommitted output; stale backups, nonce reuse, failed commits, callback errors and panics, protocol aborts | `TestRoundsCommitOnceAcrossConnections`, `TestRolledBackRoundCanBeRecomputedBeforeCommit`, `TestStaleBackupAndNonceReuseAreRejected`, `TestCommitFailuresReleaseNoOutputAndRecoverFromStore`, `TestComputationFailureAndPanicRollBack`, `TestProtocolAbortCommitsBlacklistButWithholdsOutput` in [session/guard_test.go](session/guard_test.go); end to end, DKLS23 `TestTransactionalSigningRecoversCommittedRoundAndRejectsCopies` and FROST `TestTransactionalSigningRecoversCommitmentAndConsumesRestoredNoncesOnce` in each `store_test.go` |
| Session guard: refresh quiescence and activation, durable abort and blacklist, invalid requests and updates, corrupt records, store faults and contract violations | `TestRefreshQuiescesSigningAndRequiresExplicitActivation`, `TestAbortAndBlacklistSurviveReopening` in [session/guard_test.go](session/guard_test.go); `TestInvalidRequestsAreRejectedBeforeCompute`, `TestInvalidUpdatesAreRejectedWithoutCommit`, `TestCorruptRecordsAreReportedNotRepaired`, `TestProgressAndAbortRulesAcrossOperations`, `TestRefreshAbortAndActivationConsistency`, `TestStoreErrorsPropagateAndCommitNothing`, `TestStoreContractViolationsAreReported` in [session/guard_rules_test.go](session/guard_rules_test.go) |
| Store contract checks (atomic commit, rollback on error and panic preserving complete committed records and nonce reservations, no aliasing, serialized connections, namespaces) and the test model's fault injection | `storetest.Run` via `TestModelStorageContract`, `TestConformanceRejectsDestructiveRollback` and `TestModelInjectsOneCommitFailureAndHonorsCancellation` in [session/storetest](session/storetest); a finite conformance run does not establish every part of the contract or a backend's physical durability |
| DKLS23 message enters at round 3; a presignature completes exactly one message | `TestSignPresignatureCompletesExactlyOneMessage` in [dkls23/presign_test.go](dkls23/presign_test.go); specification check in AUDIT.md FU-LOW-8 |
| Persistence version checks | DKLS23 `TestEncodingSignerSetupVersion`; FROST `TestWireFormatVersion` in each `encoding_test.go` |

## Known Limitations

- **Side-channel assurance**: No regression test establishes constant-time
  execution of the complete implementation. Dependency documentation and
  source inspection cover the fixed-width scalar methods, point ladder,
  complete addition, encoding, GF masks and `crypto/subtle` calls described
  above; their compiled timing, cache behavior and compiler transformations
  have not been independently measured across supported targets. Mathematical
  differential tests and a source search cannot supply that evidence.
- **Decoder scope**: Successful JSON decoding is not complete semantic
  validation of a key, point, scalar or transcript. Some existing persisted
  scalar decoders reduce values or accept variable widths, and some wire
  fields are checked only by the receiving protocol round. Decode messages
  into fresh objects and discard them on errors, including the base-OT
  messages that use standard `encoding/json` rather than custom decoders.
  Local checks before signing/refresh cannot detect a noncanonical original
  DKLS23 scalar once a legacy decoder has reduced it, authenticate a stored
  transcript, prove DKLS23 share-to-group-key correspondence, or establish
  correlations with a peer's secret setup material. Strict raw import
  validation remains open alongside state association; durable recovery needs
  a conforming `session.Store` backend, which this repository does not ship.
- **Randomness and protocol assumptions**: The tests do not establish
  resistance to every malicious participant or failure of the CSPRNG. Hedged
  nonce derivation does not permit repeated randomness or RNG-state cloning.
  Protocol security arguments and their corruption assumptions are not an
  implementation-wide proof for this repository.
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
  cannot see each other's records. The `session` package's revision check
  rejects the older of two copies once the authoritative store has advanced,
  provided the store itself was not restored alongside the signer.
- **DKLS23 pipelining and pre-signing**: `SignRound1` and `SignRound2` take no
  message; it enters at `SignRound3`, which is where DKLS23 §3.3 places it for
  pre-signing. Running round 1 ahead (pipelining) keeps the paper's standard
  security argument. Running rounds 1 and 2 ahead (pre-signing) rests on Groth
  and Shoup's stronger assumption; the paper calls the protocol compatible with
  it but warns that it is for those who accept the risk. A stored round-2 state
  is nonce material: it must complete exactly one message, must never rest
  unencrypted, and must be consumed or aborted before a refresh.
  `TestSignPresignatureCompletesExactlyOneMessage` backs the single-use claim;
  AUDIT.md FU-LOW-8 records the specification check.
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
| `github.com/btcsuite/btcd/btcec/v2` | dkls23  | Fixed-width scalar arithmetic and public ECDSA verification; upstream documents scalar timing properties |
| `filippo.io/edwards25519`           | frost   | Ed25519 scalar and point arithmetic, RFC 8032 encoding; timing assurance has the limits described above |
| `golang.org/x/crypto`               | dkls23  | SHAKE-256 (OT hashing, Fiat-Shamir challenges, VOLE proofs)                           |
| `github.com/stretchr/testify`       | both    | Test assertions only (not used in production code)                                    |
