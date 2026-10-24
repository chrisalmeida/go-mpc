# go-mpc — Threshold Signing Protocols for Go

[![CI](https://github.com/chrisalmeida/go-mpc/actions/workflows/ci.yml/badge.svg)](https://github.com/chrisalmeida/go-mpc/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/chrisalmeida/go-mpc.svg)](https://pkg.go.dev/github.com/chrisalmeida/go-mpc)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A Go library for **multi-party computation (MPC)** threshold signing. It implements **DKLS23 threshold ECDSA** over secp256k1 and **FROST threshold Schnorr** over Ed25519, following the published specifications step by step. Use it to build MPC wallets, distributed custody systems, and threshold signing infrastructure for Bitcoin, Ethereum, Solana, and other chains.

The library implements the cryptography only. You supply the transport between parties: each round returns the messages to send and takes the messages received.

## Protocols

| Protocol | Curve | Signature | Signing rounds | Specification |
|---|---|---|---|---|
| **[DKLS23](dkls23/)** | secp256k1 | ECDSA | 3 | [ePrint 2023/765](https://eprint.iacr.org/2023/765) (IEEE S&P 2024) |
| **[FROST](frost/)** | Ed25519 | Schnorr (EdDSA) | 2 | [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html), FROST(Ed25519, SHA-512) |

Both protocols share the same shape: a distributed key generation with no trusted dealer, flexible t-of-n thresholds, proactive key share refresh that keeps the public key fixed, identification and blacklisting of misbehaving parties, and encrypted persistence of key material through a pluggable encryptor.

## Requirements

- Go 1.26 or later (`go.mod` pins the toolchain used by CI).
- Dependencies are kept to what the cryptography needs: `bytemare/secp256k1` (constant-time point operations), `btcec` (scalar arithmetic and ECDSA verification), `filippo.io/edwards25519` (Ed25519), and `golang.org/x/crypto` (SHAKE-256).

```bash
go get github.com/chrisalmeida/go-mpc
```

## DKLS23 — Threshold ECDSA over secp256k1

Implementation of "Threshold ECDSA in Three Rounds" (Doerner, Kondi, Lee, shelat). Three signing rounds, no trusted dealer. See [SECURITY.md](SECURITY.md) for the evidence supporting implementation behavior and the limits of timing assurance.

**How it is put together**

- **Key generation** — commit-then-reveal Feldman VSS (Protocol 7.1). Parties commit to their Feldman commitments and shares before anything is revealed, so a party cannot choose its polynomial after seeing the others'.
- **One-time pairwise setup** — the λc base OTs of the Masny-Rindal endemic OT (§8.1), plus an FZero seed, per pair of parties. These seeds are the only pairwise material that is stored.
- **Per-session OT extension and VOLE** — every signing session runs a fresh KOS15 OT-extension batch with the one-message Fiat-Shamir consistency check of §5.1, and derives a fresh random VOLE (Protocol 5.2) from it. Session correlations are never reused across signing sessions.
- **Signing** — Protocol 3.6: commit to the nonce share, multiply through the VOLE, verify the consistency checks, combine, and verify the final ECDSA signature before releasing it.
- **Refresh** — KMOS21 proactive refresh re-randomizes the Shamir shares, the base-OT seeds, and the FZero seeds without changing the public key.
- **Cheating detection** — a party whose OT-extension batch, VOLE proof, decommitment, or check values fail verification is identified and blacklisted. Signing rejects that party while the blacklist entry is retained; callers must persist it and prevent rollback.

**Quick start**

```go
import "github.com/chrisalmeida/go-mpc/dkls23"

// 1. Key generation (each party runs its own side; messages go over your transport).
cfg := dkls23.DKGPartyConfig{MyID: 1, AllIDs: []int{1, 2, 3}, Threshold: 2}
r1, priv, err := dkls23.DKGRound1(cfg)          // broadcast r1 (commitments only)
r2, err := dkls23.DKGRound2(cfg, priv, peersR1)  // after all peers' r1 arrived; send r2
share, pubKey, err := dkls23.DKGFinalize(cfg, priv, allR1, allR2)
priv.Zero()

// 2. One-time pairwise setup with every other party (both directions + FZero).
//    As base-OT receiver (you are Alice for the i→j direction):
state, msg, err := dkls23.BaseOTReceiverRound1(sigma)   // send msg
seeds, err := dkls23.BaseOTReceiverFinalize(state, reply)
//    As base-OT sender (you are Bob for the j→i direction):
seeds0, seeds1, reply, err := dkls23.BaseOTSenderRound2(msg)
//    Store the results in SignerSetup.AliceBaseOT / SignerSetup.BobBaseOT,
//    and the FZero seed (FZeroSetupRound1 / FZeroSetupFinalize) in FZeroSeeds.

// 3. Signing: each session uses a fresh session id.
st1, out1, err := dkls23.SignRound1(setup, sigID, signers)          // out1[j] → party j
st2, out2, err := dkls23.SignRound2(setup, st1, inbound1)           // out2[j] → party j
frags, err := dkls23.SignRound3(setup, st2, message, inbound2)      // frags[j] → party j
rx, err := dkls23.ComputeRx(noncePoints)
r, s, err := dkls23.SignCombine(setup, &rx, &myW, &myU, inboundFrags, message)
```

The [example/dkls23](example/dkls23/) program runs the whole flow for three in-process parties, including persistence and refresh:

```bash
# Run from the repository root. Generate a key and choose a new directory once.
export MPC_WRAPPING_KEY="$(openssl rand -hex 32)"
export MPC_DEMO_DIR="$(mktemp -d)"
go -C example/dkls23 run .
# Run again with the same key and directory to reload the group.
go -C example/dkls23 run .
```

## FROST — Threshold Schnorr over Ed25519

Implementation of RFC 9591 with the FROST(Ed25519, SHA-512) ciphersuite. Two signing rounds, no trusted dealer, and signatures that verify with `crypto/ed25519`.

**How it is put together**

- **Key generation** — the FROST paper's KeyGen (Figure 1): Feldman VSS with a Schnorr proof of knowledge of each party's constant term, bound to a caller-supplied context string and verified before any share is sent. RFC 9591 does not specify a DKG, so this is the paper's construction.
- **Signing and aggregation** — RFC 9591 §5: hedged nonce generation, binding factors, group commitment, signature shares, and share verification for identifiable abort. The Appendix E.1 test vectors are reproduced exactly by the test suite.
- **Element decoding** — received protocol points go through the RFC 9591 §6.1 `DeserializeElement` rules: canonical encoding, not the identity, in the prime-order subgroup. Public signature verification follows the separate decoding rules below.
- **Verification** — the cofactored equation of RFC 9591 §6.1 on top of RFC 8032 decoding; honestly produced signatures are also accepted by `crypto/ed25519.Verify`.
- **Refresh** — zero-constant Feldman polynomials re-randomize the shares and verification shares without changing the public key.

**Quick start**

```go
import "github.com/chrisalmeida/go-mpc/frost"

// 1. Key generation. Context binds the proofs of knowledge to this DKG session.
cfg := frost.DKGPartyConfig{MyID: 1, AllIDs: []int{1, 2, 3}, Threshold: 2, Context: sessionContext}
r1, coeffs, err := frost.DKGRound1(cfg)             // broadcast r1
r2, err := frost.DKGRound2(cfg, coeffs, allR1)       // verifies every proof first; send r2
keyShare, err := frost.DKGFinalize(cfg, coeffs, allR1, allR2)

// 2. Signing.
signer := frost.NewSignerState(keyShare)
st, commitment, err := frost.SignRound1(signer, signers)             // broadcast commitment
share, err := frost.SignRound2(signer, st, &frost.Round2Input{Message: msg, AllCommitments: allCommitments})
sig, err := frost.Aggregate(allCommitments, allShares, msg, keyShare.PublicKey, verificationShares, signers)

// 3. Verify.
ok := frost.Verify(keyShare.PublicKey, msg, sig)   // or ed25519.Verify(pk, msg, sig.Bytes())
```

The [example/frost](example/frost/) program runs a 2-of-3 flow with every signer subset, persistence, and refresh:

```bash
# Run from the repository root. Generate a key and choose a new directory once.
export MPC_WRAPPING_KEY="$(openssl rand -hex 32)"
export MPC_DEMO_DIR="$(mktemp -d)"
go -C example/frost run .
go -C example/frost run .
```

Both online demos use `session.Memory` for private round state and the example
file store for encrypted signer state and committed outputs. Keep the same
wrapping key and store directory between runs. For a separate demo group, choose
a new empty directory. Legacy directories containing `enc.key` require explicit
migration; the demos never replace them automatically.

## What the library does not do

- **Transport, authentication, and broadcast.** Both protocols assume authenticated point-to-point channels and, for identifiable abort, a coordinator or broadcast that does not equivocate. See [SECURITY.md](SECURITY.md).
- **Session management.** Callers generate the session ids. DKLS23 rejects a session id that the setup has already used in the current epoch (`SessionIDReusedError`) and runs each round of a session exactly once, but two copies of a setup restored from the same snapshot cannot see each other's records, so ids must still be unique in practice. FROST DKGs need a fresh context per run. The example programs show one way to do both.
- **Crash recovery and refresh coordination.** Callers must durably record DKLS23 session reservations before sending outputs, prevent reuse of the same private session state across restored copies, and authenticate fresh peer refresh transcripts. The library rejects duplicate refresh finalization on live signer objects; it does not coordinate distributed epoch activation or recovery. The `session` package implements the reservation, checkpoint, nonce-marker and refresh-activation bookkeeping over a transactional store you supply; see [session/README.md](session/README.md) and [SECURITY.md](SECURITY.md).
- **Resharing.** Refresh keeps the same parties and threshold. Adding or removing parties, or changing t or n, is not supported.
- **Key derivation.** There is no BIP32-style derivation of child keys.

## Unreleased hardening changes

FROST serializes round-2 calls on one `SignerState`; copies of a returned
`Round1State` share a consumption guard with its own mutex. DKLS23 replaces
variable-time secret point operations and secret FZero reduction with
constant-time primitives. Treat exported state fields as read-only.

Both packages reject repeated application of a completed refresh contribution
on a live signer. Rejected custom JSON imports leave their receivers unchanged;
successful decoding does not imply complete semantic validation. The earlier security fixes retained plaintext formats, protocol transcripts and restoration behavior;
the RFC 9591 Appendix E.1 vectors and fresh-VOLE regression remain unchanged.

Signing and refresh now reject malformed local configuration and key material
before use. Signing rejects unconfigured participants; DKLS23 also checks the
selected peers' setup material and locally recomputable private round state.
Valid pending sessions still resume after restoration. These checks do not
authenticate stored documents or provide durable replay protection; see
[AUDIT.md](AUDIT.md), FU-MED-10.

The new `session` package is a storage-agnostic progress guard for both
protocols: at most one committed result per round, outputs cached for
retransmission after a lost acknowledgement, nonce markers that reject cloned
randomness, a revision check that rejects stale backups, and a prepare/activate
gate for refresh. It needs a transactional `session.Store` from the
application; the example module includes a Linux/macOS file adapter, separate from the production library. Rolled-back
attempts can be recomputed by a later explicit call using freshly decoded
checkpoints. See [session/README.md](session/README.md) and AUDIT.md FU-MED-6.

Cold signing now supports shutting down between signing or refresh rounds for
both protocols. Each package's `SessionCodec` restores fresh authoritative state,
runs the existing protocol round, and returns encrypted key, private round and
outbound message containers to `session.Advance`. Open committed receipt bytes
with `codec.OpenOutput` before transport; recover identical committed ciphertext
with `session.Output` after a lost acknowledgement. Complete or
abort unused signing operations before refresh. Activate a prepared refresh only
after coordinating with every participant.

The [envelope package](envelope/README.md) binds private state to protocol, kind,
version, group key, party, epoch, operation and round. Applications supply
**authenticated** encryption, trusted key bindings, transport and a conforming
`session.Store`. `Request.Mode` defaults to resumable storage. Online signers can
use `session.Memory.Advance` to keep private round state out of storage; after
losing that process state, abort the pending operation and choose a fresh ID.
Confirmed rounds clear superseded in-memory checkpoint buffers; commit errors
retain the candidates needed to follow authoritative progress.
No object or process identity is required for resumable signing.

The [cold FROST](example/cold-frost/main.go) and
[cold DKLS23](example/cold-dkls23/main.go) demos exchange protocol message files
between device directories, launching a new process for every signing round:

```bash
# Demo keys only. Keep this wrapping key available across all device commands.
export MPC_WRAPPING_KEY="$(openssl rand -hex 32)"
mpc_frost_dir=$(mktemp -d)
mpc_dkls_dir=$(mktemp -d)
go -C example/cold-frost run . demo "$mpc_frost_dir"
go -C example/cold-dkls23 run . demo "$mpc_dkls_dir"
```

`demo` runs the full command sequence automatically. To drive FROST manually,
keep the wrapping key above and use a fresh directory:

```bash
mpc_cold_dir=$(mktemp -d)
mpc_operation=$(openssl rand -hex 16)
go -C example/cold-frost run . init "$mpc_cold_dir"
printf '%s' 'offline file transfer signing' > "$mpc_cold_dir/message.txt"
go -C example/cold-frost run . commit "$mpc_cold_dir/device-1" "$mpc_operation" "$mpc_cold_dir/commitment-1.json"
go -C example/cold-frost run . commit "$mpc_cold_dir/device-2" "$mpc_operation" "$mpc_cold_dir/commitment-2.json"
go -C example/cold-frost run . request "$mpc_cold_dir" "$mpc_operation" "$mpc_cold_dir/message.txt" "$mpc_cold_dir/commitment-1.json" "$mpc_cold_dir/commitment-2.json" "$mpc_cold_dir/request.json"
go -C example/cold-frost run . sign "$mpc_cold_dir/device-1" "$mpc_operation" "$mpc_cold_dir/request.json" "$mpc_cold_dir/share-1.json"
go -C example/cold-frost run . sign "$mpc_cold_dir/device-2" "$mpc_operation" "$mpc_cold_dir/request.json" "$mpc_cold_dir/share-2.json"
go -C example/cold-frost run . aggregate "$mpc_cold_dir" "$mpc_cold_dir/request.json" "$mpc_cold_dir/share-1.json" "$mpc_cold_dir/share-2.json" "$mpc_cold_dir/signature.bin"
```

FROST's `request` command takes commitment files in configured participant order
(device 1, then device 2). Its signature file contains the standard 64-byte
Ed25519 signature, checked with `crypto/ed25519` before writing.

For DKLS23, the coordinator builds each recipient's request from the previous
round's replies. Each `round` invocation runs on that party's device:

```bash
mpc_cold_dir=$(mktemp -d)
mpc_operation=$(openssl rand -hex 16)
go -C example/cold-dkls23 run . init "$mpc_cold_dir"
printf '%s' 'offline file transfer signing' > "$mpc_cold_dir/message.txt"
for round in 1 2 3; do
  go -C example/cold-dkls23 run . request "$mpc_cold_dir" "$mpc_operation" "$round" "$mpc_cold_dir/message.txt"
  for party in 1 2 3; do
    go -C example/cold-dkls23 run . round "$mpc_cold_dir/device-$party" "$mpc_cold_dir/request-$round-$party.json" "$mpc_cold_dir/round-$round-$party.json"
  done
done
go -C example/cold-dkls23 run . combine "$mpc_cold_dir" "$mpc_operation" "$mpc_cold_dir/message.txt" "$mpc_cold_dir/signature.der"
```

DKLS23 writes a DER-encoded ECDSA signature over SHA-256 of the message file.
Both demos have `--help`. Repeating a device command for the same operation and
round recovers its committed output, even after a failed output-file write.
A changed message on retry still returns the original result. Use a fresh
operation ID for a new signature. A device directory can move between machines
with its wrapping key and authoritative progress; retire the old copy rather
than operate both copies independently.

`init` uses colocated demo DKG; each demo uses one environment wrapping key for
all its devices. Production deployments provision separate devices and keys,
authenticate public configuration and provide authenticated confidential file
transport. Only protocol messages cross devices; encrypted key/private round
checkpoints and authoritative progress stay in each device directory. Neither
demo implements a message approval policy. The example file store targets local
Linux/macOS filesystems; it does not detect a restored old store snapshot.
The corrected adapter locates existing partitions independently of Go's Gob
type-registration order and retains their filenames and pending progress;
duplicate scope files are rejected. Use the corrected adapter in every process
accessing a device store (AUDIT.md FU-MED-15).
See the single [design note](docs/encrypted-state-and-cold-signing.md) for format
details and [SECURITY.md](SECURITY.md) for assurance limits.

DKLS23 pipelining can stop after round 1. Running round 2 without a chosen message
requires `SessionSignInput.AllowPreSigning = true`, accepting the paper's §3.3
stronger assumption. The message is used cryptographically only at round 3;
applications remain responsible for choosing and approving it.

### Encrypted-import migration (breaking)

`UnmarshalEncrypted(blob, enc, expected)` now requires `KeyBinding` in both
packages. Supply the public key, party and epoch from trusted application records:

```go
expected := dkls23.KeyBinding{PublicKey: trustedPK, PartyID: myID, Epoch: epoch}
setup, err := dkls23.UnmarshalEncrypted(blob, enc, expected)
```

`SetupEncryptor` is an alias of `envelope.Encryptor`; existing authenticated
implementations keep their method signatures. Ciphertext now uses a versioned
bound envelope. Legacy unbound ciphertext is deliberately rejected: explicitly
`enc.Decrypt`, call the existing plaintext importer, validate its binding and
progress against trusted records, then reseal it with `MarshalEncrypted`. Preserve
legitimate pending state and its authoritative progress during migration; do not
restart it or reset reservations automatically. Plaintext and protocol message
formats remain unchanged. Bare FROST `KeyShare` is epoch zero; use
`MarshalSignerEncrypted` / `UnmarshalSignerEncrypted` to retain epochs and
blacklists. `Binding()` is useful when exporting an already trusted live key;
reading an untrusted blob is not a way to establish the expected binding.
When migrating a refreshed bare FROST key, restore its known epoch and blacklist
into a `SignerState` before sealing. Adopting an already pending operation into
the guard also requires its trusted operation record, cached outputs and spent
nonce history; the guard does not infer these from a key blob. Existing direct
protocol restoration remains supported.

Store adapters must retain the new operation `Mode` field and accept 32-byte
nonce-marker keys. Existing zero modes remain resumable, and legacy raw nonce
reservations remain checked. Retain authoritative progress independently of
restorable signer backups; rolling back both defeats the guard.

## Upgrading from v0.2.x

v0.3.0 changes the protocol structure, the APIs, and the persisted formats. It is not wire- or storage-compatible with v0.2.x or earlier.

- **Stored key material must be regenerated.** `SignerSetup` (DKLS23) and `KeyShare` / `SignerState` (FROST) now carry a wire-format version and reject blobs without it. Run a fresh key generation and setup; the demos do this when their `shares/` directory is removed.
- **DKLS23 key generation** is commit-then-reveal. `DKGRound1` returns a `*DKGPrivateState` instead of raw coefficients, `DKGRound2` requires every other party's round 1 output, and the Feldman commitments are released in round 2.
- **DKLS23 pairwise setup** stores only base-OT seeds (`SignerSetup.AliceBaseOT`, `SignerSetup.BobBaseOT`). The base OT is Masny-Rindal and the receiver speaks first: `BaseOTReceiverRound1` → `BaseOTSenderRound2` → `BaseOTReceiverFinalize`. The former VOLE setup functions, `SignSetupPairwise`, `SignCounter`, and the persisted VOLE state are gone.
- **DKLS23 round 1 messages** carry the session's OT-extension batch, so they are larger than before and specific to each counterparty.
- **FROST key generation** adds `DKGPartyConfig.Context`, which must be non-empty and identical across parties, and the proof fields on `DKGRound1Output`; `DKGRound2` now takes all parties' round 1 outputs and verifies the proofs.
- **FROST protocol input validation is stricter.** Non-canonical point encodings, the identity, and small-order or mixed-order points are rejected in protocol elements. Public signature verification retains RFC 8032 decoding and the RFC 9591 cofactored equation.

The reasons for these changes are documented in the 2026-10-16 follow-up section of [AUDIT.md](AUDIT.md), including a confirmed key-recovery flaw in the v0.x DKLS23 implementation.

## Project Structure

```
dkls23/              Threshold ECDSA (secp256k1)
  dkg.go             Commit-then-reveal distributed key generation (Protocol 7.1)
  sign.go            3-round threshold signing with per-session VOLE (Protocol 3.6)
  refresh.go         Proactive refresh of shares, base-OT seeds, FZero seeds (KMOS21)
  vole.go            Random vector OLE (Protocol 5.2)
  ot.go              Masny-Rindal endemic base OT (one-time setup)
  ot_extension.go    KOS15 OT extension with Fiat-Shamir consistency check
  gf128.go           Constant-time GF(2^128) arithmetic for the consistency check
  curve.go           Constant-time secp256k1 point operations and SEC1 encoding
  commitment.go      FCom / FZero primitives
  setup_messages.go  Wire types for the one-time pairwise setup
  encoding.go        Versioned JSON wire format
  persistence.go     Bound encrypted key/setup import and export
  state_encoding.go  Private round and refresh checkpoint envelopes
  session.go         Library signing and refresh callbacks for session.Advance
  errors.go          Typed error categories
  params.go          Security parameters and constants
frost/               Threshold Schnorr / Ed25519 (RFC 9591)
  keygen.go          Distributed key generation with proofs of knowledge
  sign.go            2-round threshold signing + aggregation
  refresh.go         Proactive key share refresh
  verify.go          Cofactored Ed25519 verification
  hash.go            H1-H5 and the DKG proof hash
  encoding.go        Versioned JSON wire format
  persistence.go     Bound encrypted key and signer-state import and export
  state_encoding.go  Private nonce and refresh checkpoint envelopes
  session.go         Signing, refresh and outbound-output codecs
  errors.go          Typed error categories
  params.go          Ciphersuite constants and element decoding
session/             Transactional progress guard over a caller-supplied store
  store.go           Scope, versions, records, the Store contract, sentinel errors
  guard.go           Initialize, Advance, Output, Abort, Blacklist, Activate
  storetest/         Store conformance suite and in-memory fault-injecting model
internal/statejson/  Canonical JSON validation for private envelopes
envelope/            Context-bound container over caller-authenticated encryption
  envelope.go        Seal, Open, Peek, encryptor interfaces and typed errors
  context.go         Canonical context encoding and metadata validation
example/
  shared/            AES-GCM envelope encryptor and example Linux/macOS file store
  dkls23/            Online 3-of-3 DKLS23 demo with persistence and refresh
  frost/             Online 2-of-3 FROST demo with persistence and refresh
  cold-dkls23/       Offline 3-of-3 ECDSA commands with per-party request routing
  cold-frost/        Offline 2-of-2 Ed25519 commands with a request builder
```

## Development

```bash
make test          # run all tests
make test-race     # run with the race detector
make lint          # gofmt, go vet, staticcheck
make fuzz          # run every fuzz target briefly
make vuln          # govulncheck
make examples      # vet/race-test examples; run online reloads and both cold demos
make ci            # everything CI runs
```

## Security

DKLS23 uses `bytemare/secp256k1` for point operations and `btcec.ModNScalar` for scalar arithmetic, including reduction of secret FZero outputs. Its OT choice bits select with masks and `crypto/subtle` copies. FROST uses `filippo.io/edwards25519`. These source choices rely on the dependency behavior documented in GoDoc; their compiled timing, cache behavior and memory erasure have not been independently established. [SECURITY.md](SECURITY.md#evidence-and-test-coverage) maps functional claims to tests and records those assurance limits.

Both packages have had automated reviews. A 2026-10-16 follow-up found a previously missed critical key-recovery flaw; further hardening found nonce concurrency, curve-operation and secret-reduction defects. [AUDIT.md](AUDIT.md) records fixes, evidence limits and open findings. Passing tests does not establish cryptographic security.

[SECURITY.md](SECURITY.md) describes the security assumptions, limitations, disclosure process and remaining production review gates. These include an independent specialist MPC audit of a pinned release and verification of its fixes; this library is not approved for production custody.

## Authors

Co-authored by [Chris Almeida](https://github.com/chrisalmeida) and [Claude Code](https://claude.ai/code) (Anthropic Claude Fable 5.1).

## References

- Doerner, Kondi, Lee, shelat. "Threshold ECDSA in Three Rounds." IEEE S&P 2024. [ePrint 2023/765](https://eprint.iacr.org/2023/765)
- Kondi, Magri, Orlandi, Shlomovits. "Refresh When You Wake Up." IEEE S&P 2021. [ePrint 2019/1328](https://eprint.iacr.org/2019/1328)
- Keller, Orsini, Scholl. "Actively Secure OT Extension with Optimal Overhead." CRYPTO 2015. [ePrint 2015/546](https://eprint.iacr.org/2015/546)
- Masny, Rindal. "Endemic Oblivious Transfer." CCS 2019. [ePrint 2019/706](https://eprint.iacr.org/2019/706)
- Connolly, Komlo, Goldberg, Wood. "Two-Round Threshold Schnorr Signatures with FROST." IETF RFC 9591, June 2024. [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html)
- Komlo, Goldberg. "FROST: Flexible Round-Optimized Schnorr Threshold Signatures." SAC 2020. [ePrint 2020/852](https://eprint.iacr.org/2020/852)
- Josefsson, Liusvaara. "Edwards-Curve Digital Signature Algorithm (EdDSA)." IETF RFC 8032, January 2017. [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).
