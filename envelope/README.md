# Encrypted state envelopes

This package implements the container layer of the [cold-signing design](../docs/encrypted-state-and-cold-signing.md): a container binding encrypted bytes to their expected protocol, kind, payload wire version, group key, party, epoch, operation and round. It supplies `Seal`, `Open`, `Peek`, `Context`, `Encryptor` and optional `ContextEncryptor`.

DKLS23 and FROST persistence wrappers compose these bindings automatically. Their `SessionCodec` callbacks combine encrypted key and round checkpoints with `session.Advance`. See the root README for the restartable cold-signing workflow and the encrypted-import migration.

## Files

| File | Purpose |
| --- | --- |
| `envelope.go` | Interfaces, typed errors, framing, `Seal`, `Open`, `Peek`, context comparison |
| `binding.go` | Trusted public key, party and epoch binding used by protocol persistence APIs |
| `context.go` | Context fields, protocol/kind combinations, canonical encoding and strict header decoding |
| `envelope_test.go` | Authenticated legacy/AAD round trips, context rejection, header substitution, ownership and cipher failures |
| `decoding_test.go` | Malformed framing/fields and authenticated invalid inner documents |
| `fuzz_test.go` | `FuzzOpen` and `FuzzPeek` |

## Format version 1

The container is `version byte || uint16(context length) || context || ciphertext`. Ciphertext encrypts `context || payload`. Context has eight fields, each preceded by a two-byte byte-length, in this order:

| Field | Encoding |
| --- | --- |
| `Protocol` | Raw bytes: `dkls23` or `frost` |
| `Kind` | Raw bytes: `setup`, `key`, `signer`, `sign-1`, `sign-2`, `refresh-1`, `refresh-2`, `sign-output`, `refresh-output` |
| `WireVersion` | Four-byte unsigned integer, nonzero |
| `PublicKey` | Raw encoding, 33 bytes for DKLS23 or 32 for FROST |
| `PartyID` | Four-byte unsigned integer, 1 through 2³¹−1 |
| `Epoch` | Eight-byte unsigned integer, representable as a nonnegative Go `int` |
| `OperationID` | Opaque bytes in a Go string; empty for key material |
| `Round` | Four-byte unsigned integer |

All integers are big-endian; the complete context fits 65,535 bytes. `setup` is DKLS23-only; `key` and `signer` are FROST-only. Key kinds require round zero and an empty operation. `sign-1` and `refresh-1` require round one and a nonempty operation; `sign-2` and `refresh-2` use round two. `sign-2` is DKLS23-only. `sign-output` binds rounds 1–3 for DKLS23 or 1–2 for FROST; `refresh-output` binds rounds 1–2. Outbound containers prevent cached messages, including secret refresh shares, from being loaded as private round state. Container and payload wire versions are distinct.

Metadata shape and public-key width are checked. Actual curve points, private-state semantics and correspondence to the context must be validated by the protocol codec.

## Opening and encryptor contracts

`Seal(enc, binding, privateBytes)` puts a context copy in the clear header and another in the encrypted plaintext. `Open(enc, expectedBinding, blob)` checks the header before invoking the decryptor, then compares the decrypted prefix with the expected canonical bytes before returning an owned payload. It uses trusted expected lengths and field boundaries rather than interpreting decrypted length prefixes before matching. Both comparisons use `crypto/subtle.ConstantTimeCompare`; context fields and lengths are public.

`Peek(blob)` returns owned header metadata without authenticating it. Select `expectedBinding` from trusted records. Errors are `*Error` values identifying `Op`, `Field` and an unwrap-able cause; underlying encryptor errors remain available through `errors.Is`/`errors.As`. Failure returns no payload.

The supplied encryptor **must authenticate ciphertext**. An embedded copy cannot provide integrity with a malleable, unauthenticated cipher. `Encryptor` keeps the existing two-method shape. Optional `ContextEncryptor` adds `EncryptContext(plaintext, associatedData)` and `DecryptContext(ciphertext, associatedData)`. When implemented, these methods replace the plain methods and receive the complete clear header as associated data. The package chooses no cipher or keys; tests use disposable keys with Go's AES-GCM implementation.

Encryptors receive owned buffers and may work in place. Returned buffers belong to the envelope and can be cleared after use. Caller payloads, contexts and blobs are preserved. Temporary plaintext is cleared on success and failure, including partial plaintext returned with an error. Go may retain other copies; physical erasure is not established.

An envelope can be reopened with its matching context. Replay, rollback, durable storage and distributed epoch coordination require the session guard and caller's backend. The container cannot prove that a codec encoded the correct state or that an encryptor implements its contract.

## Evidence

`TestCanonicalContextEncoding` supplies an independent byte vector. `TestRoundTripAllKindsAndEncryptorInterfaces` covers both interfaces and all kinds. `TestOpenRejectsEveryContextFieldBeforeDecryption` checks every field and that the decryptor was not called. `TestSplicedHeaderIsRejectedAfterDecryption` tests embedded binding without AAD and authentication rejection with AAD. Other tests reject truncation, modified ciphertext, wrong keys, malformed headers/fields and authenticated invalid inner documents; they verify buffer ownership, in-place operation and cipher failures. The fuzz targets preserve their inputs; `FuzzOpen` asserts no payload on errors and round trips accepted output.
