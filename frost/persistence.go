package frost

import (
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

// Binding returns a key share's public persistence binding. A bare KeyShare has
// no epoch; persist SignerState to retain refresh epochs and blacklist decisions.
func (ks *KeyShare) Binding() KeyBinding {
	if ks == nil {
		return KeyBinding{}
	}
	return KeyBinding{PublicKey: append([]byte(nil), ks.PublicKey...), PartyID: ks.ID}
}

// Binding returns the signer's public persistence binding under its read lock.
func (ss *SignerState) Binding() KeyBinding {
	if ss == nil {
		return KeyBinding{}
	}
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	b := ss.KeyShare.Binding()
	b.Epoch = ss.Epoch
	return b
}

func stateContext(b KeyBinding, kind, operation string, round int) envelope.Context {
	return envelope.Context{Protocol: envelope.FROST, Kind: kind, WireVersion: WireFormatVersion,
		PublicKey: b.PublicKey, PartyID: b.PartyID, Epoch: b.Epoch, OperationID: operation, Round: round}
}

// MarshalKeyShare serializes a KeyShare to JSON.
// The output contains the secret share in plaintext — callers should
// encrypt the result before writing to disk.
func MarshalKeyShare(ks *KeyShare) ([]byte, error) {
	return json.Marshal(ks)
}

// UnmarshalKeyShare deserializes a KeyShare from JSON.
func UnmarshalKeyShare(data []byte) (*KeyShare, error) {
	var ks KeyShare
	if err := json.Unmarshal(data, &ks); err != nil {
		return nil, fmt.Errorf("frost UnmarshalKeyShare: %w", err)
	}
	return &ks, nil
}

// MarshalSignerState serializes a SignerState to JSON.
// Safe for concurrent use: acquires a read lock.
func MarshalSignerState(ss *SignerState) ([]byte, error) {
	return json.Marshal(ss)
}

// UnmarshalSignerState deserializes a SignerState from JSON.
func UnmarshalSignerState(data []byte) (*SignerState, error) {
	var ss SignerState
	if err := json.Unmarshal(data, &ss); err != nil {
		return nil, fmt.Errorf("frost UnmarshalSignerState: %w", err)
	}
	if ss.Blacklist == nil {
		ss.Blacklist = make(map[int]bool)
	}
	return &ss, nil
}

// MarshalEncrypted seals a KeyShare in a bound envelope at epoch zero.
// Persist the SignerState instead when retaining refreshed keys or blacklists.
func MarshalEncrypted(ks *KeyShare, enc SetupEncryptor) ([]byte, error) {
	if err := validateKeyShare(ks, "MarshalEncrypted"); err != nil {
		return nil, err
	}
	plaintext, err := MarshalKeyShare(ks)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	return envelope.Seal(enc, stateContext(ks.Binding(), envelope.Key, "", 0), plaintext)
}

// UnmarshalEncrypted opens a KeyShare only for a trusted expected binding.
// Legacy unbound ciphertext is rejected; see the README migration instructions.
func UnmarshalEncrypted(ciphertext []byte, enc SetupEncryptor, expect KeyBinding) (*KeyShare, error) {
	plaintext, err := envelope.Open(enc, stateContext(expect, envelope.Key, "", 0), ciphertext)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	var ks KeyShare
	if err := statejson.Decode(plaintext, &ks); err != nil {
		return nil, err
	}
	if err := validateKeyShare(&ks, "UnmarshalEncrypted"); err != nil {
		return nil, err
	}
	if expect.Epoch != 0 || ks.ID != expect.PartyID || string(ks.PublicKey) != string(expect.PublicKey) {
		return nil, &CorruptStateError{Phase: "UnmarshalEncrypted", Detail: "payload binding differs from envelope"}
	}
	return &ks, nil
}

// MarshalSignerEncrypted seals the RFC 9591 signer's key, epoch and blacklist.
func MarshalSignerEncrypted(ss *SignerState, enc SetupEncryptor) ([]byte, error) {
	// Snapshot through MarshalSignerState, whose marshaler holds the read lock.
	if ss == nil {
		return nil, &CorruptStateError{Phase: "MarshalSignerEncrypted", Detail: "missing signer"}
	}
	plaintext, err := MarshalSignerState(ss)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	snapshot, err := UnmarshalSignerState(plaintext)
	if err != nil {
		return nil, err
	}
	if err := validateSignerState(snapshot, "MarshalSignerEncrypted"); err != nil {
		return nil, err
	}
	return envelope.Seal(enc, stateContext(snapshot.Binding(), envelope.Signer, "", 0), plaintext)
}

// UnmarshalSignerEncrypted restores a signer for a trusted expected binding.
func UnmarshalSignerEncrypted(ciphertext []byte, enc SetupEncryptor, expect KeyBinding) (*SignerState, error) {
	plaintext, err := envelope.Open(enc, stateContext(expect, envelope.Signer, "", 0), ciphertext)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	var ss SignerState
	if err := statejson.Decode(plaintext, &ss); err != nil {
		return nil, err
	}
	if err := validateSignerState(&ss, "UnmarshalSignerEncrypted"); err != nil {
		return nil, err
	}
	if ss.Epoch != expect.Epoch || ss.KeyShare.ID != expect.PartyID || string(ss.KeyShare.PublicKey) != string(expect.PublicKey) {
		return nil, &CorruptStateError{Phase: "UnmarshalSignerEncrypted", Detail: "payload binding differs from envelope"}
	}
	return &ss, nil
}
