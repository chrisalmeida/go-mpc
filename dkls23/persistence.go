package dkls23

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/chrisalmeida/go-mpc/envelope"
	"github.com/chrisalmeida/go-mpc/internal/statejson"
)

// SetupEncryptor supplies authenticated encryption for persisted private state.
// See envelope.Encryptor; this package chooses no cipher or encryption key.
type SetupEncryptor = envelope.Encryptor

// KeyBinding identifies the trusted key, party and epoch expected on import.
type KeyBinding = envelope.Binding

// Binding returns this setup's public persistence binding under its read lock.
func (setup *SignerSetup) Binding() KeyBinding {
	if setup == nil {
		return KeyBinding{}
	}
	setup.mu.RLock()
	defer setup.mu.RUnlock()
	return KeyBinding{PublicKey: append([]byte(nil), setup.PubKey...), PartyID: setup.MyID, Epoch: setup.Epoch}
}

func stateContext(b KeyBinding, kind, operation string, round int) envelope.Context {
	return envelope.Context{Protocol: envelope.DKLS23, Kind: kind, WireVersion: SetupWireVersion,
		PublicKey: b.PublicKey, PartyID: b.PartyID, Epoch: b.Epoch, OperationID: operation, Round: round}
}

// MarshalSetup serializes a SignerSetup to JSON.
// The output contains the Shamir share in plaintext — callers should
// encrypt the result before writing to disk. Use MarshalEncrypted for
// a one-step encrypt-and-serialize flow.
//
// Safe for concurrent use: acquires a read lock on setup.mu.
func MarshalSetup(setup *SignerSetup) ([]byte, error) {
	if setup == nil {
		return nil, &CorruptStateError{Phase: "MarshalSetup", Detail: "missing setup"}
	}
	setup.mu.RLock()
	defer setup.mu.RUnlock()
	return json.Marshal(setup)
}

// UnmarshalSetup deserializes a SignerSetup from JSON.
// Use UnmarshalEncrypted if the data was produced by MarshalEncrypted.
func UnmarshalSetup(data []byte) (*SignerSetup, error) {
	var s SignerSetup
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("dkls23 UnmarshalSetup: %w", err)
	}
	return &s, nil
}

// MarshalEncrypted seals Protocol 3.6's persistent setup in a context-bound
// envelope. The encryptor must authenticate ciphertext; see envelope.Encryptor.
func MarshalEncrypted(setup *SignerSetup, enc SetupEncryptor) ([]byte, error) {
	if setup == nil {
		return nil, &CorruptStateError{Phase: "MarshalEncrypted", Detail: "missing setup"}
	}
	setup.mu.RLock()
	defer setup.mu.RUnlock()
	if err := validateSetupState(setup, "MarshalEncrypted"); err != nil {
		return nil, err
	}
	// Encode opaque session IDs as base64 keys in the new envelope payload.
	// encoding/json otherwise replaces invalid UTF-8 in legacy string map keys.
	snapshot := &SignerSetup{MyID: setup.MyID, AllIDs: setup.AllIDs, Threshold: setup.Threshold,
		Share: setup.Share, PubKey: setup.PubKey, AliceBaseOT: setup.AliceBaseOT, BobBaseOT: setup.BobBaseOT,
		FZeroSeeds: setup.FZeroSeeds, Blacklist: setup.Blacklist, Epoch: setup.Epoch}
	sessions := make(map[string]int, len(setup.SessionIDs))
	for id, round := range setup.SessionIDs {
		sessions[base64.RawStdEncoding.EncodeToString([]byte(id))] = round
	}
	plaintext, err := json.Marshal(boundSetupJSON{Version: 1, Setup: snapshot, SessionIDs: sessions})
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	b := KeyBinding{PublicKey: setup.PubKey, PartyID: setup.MyID, Epoch: setup.Epoch}
	return envelope.Seal(enc, stateContext(b, envelope.Setup, "", 0), plaintext)
}

// UnmarshalEncrypted opens a setup only for the caller's trusted expected binding.
// Legacy unbound ciphertext is rejected. For migration, explicitly decrypt it and
// use UnmarshalSetup, validate against trusted records, then MarshalEncrypted.
func UnmarshalEncrypted(ciphertext []byte, enc SetupEncryptor, expect KeyBinding) (*SignerSetup, error) {
	plaintext, err := envelope.Open(enc, stateContext(expect, envelope.Setup, "", 0), ciphertext)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	var wire boundSetupJSON
	if err := statejson.Decode(plaintext, &wire); err != nil {
		return nil, fmt.Errorf("dkls23 UnmarshalEncrypted: %w", err)
	}
	if wire.Version != 1 || wire.Setup == nil || len(wire.Setup.SessionIDs) != 0 || wire.SessionIDs == nil {
		return nil, &CorruptStateError{Phase: "UnmarshalEncrypted", Detail: "invalid envelope payload"}
	}
	setup := wire.Setup
	setup.SessionIDs = make(map[string]int, len(wire.SessionIDs))
	for encoded, round := range wire.SessionIDs {
		id, err := base64.RawStdEncoding.Strict().DecodeString(encoded)
		if err != nil {
			return nil, err
		}
		if len(id) == 0 || base64.RawStdEncoding.EncodeToString(id) != encoded {
			return nil, &CorruptStateError{Phase: "UnmarshalEncrypted", Detail: "invalid session identifier"}
		}
		setup.SessionIDs[string(id)] = round
	}
	if err := validateSetupState(setup, "UnmarshalEncrypted"); err != nil {
		return nil, err
	}
	if setup.MyID != expect.PartyID || setup.Epoch != expect.Epoch || string(setup.PubKey) != string(expect.PublicKey) {
		return nil, &CorruptStateError{Phase: "UnmarshalEncrypted", Detail: "payload binding differs from envelope"}
	}
	for _, round := range setup.SessionIDs {
		if round < 1 || round > 3 {
			return nil, &CorruptStateError{Phase: "UnmarshalEncrypted", Detail: "invalid signing progress"}
		}
	}
	return setup, nil
}

// The new envelope payload separates byte-exact signing IDs from legacy JSON.
// Legacy MarshalSetup/UnmarshalSetup representations are unchanged.
type boundSetupJSON struct {
	Version    int            `json:"version"`
	Setup      *SignerSetup   `json:"setup"`
	SessionIDs map[string]int `json:"session_ids"`
}
