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

- Go 1.25 or later (`go.mod` pins the toolchain used by CI).
- Dependencies are kept to what the cryptography needs: `btcec` (secp256k1), `filippo.io/edwards25519` (Ed25519), and `golang.org/x/crypto` (SHAKE-256).

```bash
go get github.com/chrisalmeida/go-mpc
```

## DKLS23 — Threshold ECDSA over secp256k1

Implementation of "Threshold ECDSA in Three Rounds" (Doerner, Kondi, Lee, shelat). Three signing rounds, no trusted dealer, constant-time operations on secret values.

**How it is put together**

- **Key generation** — commit-then-reveal Feldman VSS (Protocol 7.1). Parties commit to their Feldman commitments and shares before anything is revealed, so a party cannot choose its polynomial after seeing the others'.
- **One-time pairwise setup** — the λc base OTs of the Masny-Rindal endemic OT (§8.1), plus an FZero seed, per pair of parties. These seeds are the only pairwise material that is stored.
- **Per-session OT extension and VOLE** — every signing session runs a fresh KOS15 OT-extension batch with the one-message Fiat-Shamir consistency check of §5.1, and derives a fresh random VOLE (Protocol 5.2) from it. Nothing produced inside a session is stored or reused.
- **Signing** — Protocol 3.6: commit to the nonce share, multiply through the VOLE, verify the consistency checks, combine, and verify the final ECDSA signature before releasing it.
- **Refresh** — KMOS21 proactive refresh re-randomizes the Shamir shares, the base-OT seeds, and the FZero seeds without changing the public key.
- **Cheating detection** — a party whose OT-extension batch, VOLE proof, decommitment, or check values fail verification is identified and excluded from all future sessions.

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
cd example/dkls23 && go run .
```

## FROST — Threshold Schnorr over Ed25519

Implementation of RFC 9591 with the FROST(Ed25519, SHA-512) ciphersuite. Two signing rounds, no trusted dealer, and signatures that verify with `crypto/ed25519`.

**How it is put together**

- **Key generation** — the FROST paper's KeyGen (Figure 1): Feldman VSS with a Schnorr proof of knowledge of each party's constant term, bound to a caller-supplied context string and verified before any share is sent. RFC 9591 does not specify a DKG, so this is the paper's construction.
- **Signing and aggregation** — RFC 9591 §5: hedged nonce generation, binding factors, group commitment, signature shares, and share verification for identifiable abort. The Appendix E.1 test vectors are reproduced exactly by the test suite.
- **Element decoding** — every received point goes through the RFC 9591 §6.1 `DeserializeElement` rules: canonical encoding, not the identity, in the prime-order subgroup.
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
cd example/frost && go run .
```

## What the library does not do

- **Transport, authentication, and broadcast.** Both protocols assume authenticated point-to-point channels and, for identifiable abort, a coordinator or broadcast that does not equivocate. See [SECURITY.md](SECURITY.md).
- **Session management.** Callers must use a fresh session id for every DKLS23 signing session and a fresh context for every FROST DKG. The example programs show one way to do this.
- **Resharing.** Refresh keeps the same parties and threshold. Adding or removing parties, or changing t or n, is not supported.
- **Key derivation.** There is no BIP32-style derivation of child keys.

## Upgrading from v0.x

This major version changes the protocol structure, the APIs, and the persisted formats. It is not wire- or storage-compatible with v0.x.

- **Stored key material must be regenerated.** `SignerSetup` (DKLS23) and `KeyShare` / `SignerState` (FROST) now carry a wire-format version and reject blobs without it. Run a fresh key generation and setup; the demos do this when their `shares/` directory is removed.
- **DKLS23 key generation** is commit-then-reveal. `DKGRound1` returns a `*DKGPrivateState` instead of raw coefficients, `DKGRound2` requires every other party's round 1 output, and the Feldman commitments are released in round 2.
- **DKLS23 pairwise setup** stores only base-OT seeds (`SignerSetup.AliceBaseOT`, `SignerSetup.BobBaseOT`). The base OT is Masny-Rindal and the receiver speaks first: `BaseOTReceiverRound1` → `BaseOTSenderRound2` → `BaseOTReceiverFinalize`. The former VOLE setup functions, `SignSetupPairwise`, `SignCounter`, and the persisted VOLE state are gone.
- **DKLS23 round 1 messages** carry the session's OT-extension batch, so they are larger than before and specific to each counterparty.
- **FROST key generation** adds `DKGPartyConfig.Context` and the proof fields on `DKGRound1Output`; `DKGRound2` now takes all parties' round 1 outputs and verifies the proofs.
- **FROST input validation is stricter.** Non-canonical point encodings, the identity, and small-order or mixed-order points are rejected wherever an element is received.

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
  commitment.go      FCom / FZero primitives
  setup_messages.go  Wire types for the one-time pairwise setup
  encoding.go        Versioned JSON wire format
  persistence.go     Encrypted key share serialization
  errors.go          Typed error categories
  params.go          Security parameters and constants
frost/               Threshold Schnorr / Ed25519 (RFC 9591)
  keygen.go          Distributed key generation with proofs of knowledge
  sign.go            2-round threshold signing + aggregation
  refresh.go         Proactive key share refresh
  verify.go          Cofactored Ed25519 verification
  hash.go            H1-H5 and the DKG proof hash
  encoding.go        Versioned JSON wire format
  persistence.go     Encrypted key share serialization
  errors.go          Typed error categories
  params.go          Ciphersuite constants and element decoding
example/
  shared/            AES-256-GCM encryptor (shared by both demos)
  dkls23/            Complete 3-of-3 DKLS23 demo
  frost/             Complete 2-of-3 FROST demo
```

## Development

```bash
make test          # run all tests
make test-race     # run with the race detector
make lint          # gofmt, go vet, staticcheck
make fuzz          # run every fuzz target briefly
make vuln          # govulncheck
make examples      # build and run both demos
make ci            # everything CI runs
```

## Security

Secret scalar arithmetic is constant-time in both packages, with no `math/big` operations on secret data. DKLS23 handles its OT choice bits and VOLE selections with masks rather than branches; FROST relies on `filippo.io/edwards25519` constant-time arithmetic. Both use Fermat's little theorem for modular inversion.

Both packages were reviewed by an automated audit, and a 2026-10-16 follow-up review found that the first audit had missed a critical key-recovery flaw in dkls23 along with several deviations from the cited specifications. All findings from both reviews are resolved; [AUDIT.md](AUDIT.md) has the full report, including the proof of concept that confirmed the critical finding.

[SECURITY.md](SECURITY.md) describes the threat model, constant-time guarantees, known limitations, and the responsible disclosure process. An independent third-party audit by a firm specializing in MPC protocols is recommended before production deployment with real assets.

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
