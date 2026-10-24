package dkls23

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/chrisalmeida/go-mpc/envelope"
	"github.com/chrisalmeida/go-mpc/internal/statejson"
)

// PrivateStateVersion versions the new refresh private-state JSON schema.
const PrivateStateVersion = 1

// MarshalRound1Encrypted seals Protocol 3.6's round-1 state for its signing id.
// Session progress must be authoritative; envelopes do not prevent rollback.
func MarshalRound1Encrypted(setup *SignerSetup, state *Round1State, enc SetupEncryptor) ([]byte, error) {
	if setup == nil {
		return nil, fmt.Errorf("dkls23 MarshalRound1Encrypted: missing setup")
	}
	setup.mu.RLock()
	defer setup.mu.RUnlock()
	if err := validateRound1State(setup, state, "MarshalRound1Encrypted"); err != nil {
		return nil, err
	}
	return sealRound(setup, state, state.SigID, 1, enc)
}

// UnmarshalRound1Encrypted restores the expected signing id's round-1 state.
func UnmarshalRound1Encrypted(setup *SignerSetup, operation string, ciphertext []byte, enc SetupEncryptor) (*Round1State, error) {
	b := setup.Binding()
	plaintext, err := envelope.Open(enc, stateContext(b, envelope.Sign1, operation, 1), ciphertext)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	var wire boundSigningJSON
	if err := statejson.Decode(plaintext, &wire); err != nil {
		return nil, err
	}
	if wire.Version != 1 || wire.Round1 == nil || wire.Round2 != nil || wire.Round1.SigID != "" || string(wire.OperationID) != operation {
		return nil, fmt.Errorf("dkls23 UnmarshalRound1Encrypted: signing payload mismatch")
	}
	state := wire.Round1
	state.SigID = operation
	if setup == nil {
		return nil, fmt.Errorf("dkls23 UnmarshalRound1Encrypted: missing setup")
	}
	setup.mu.RLock()
	defer setup.mu.RUnlock()
	if state.SigID != operation {
		return nil, fmt.Errorf("dkls23 UnmarshalRound1Encrypted: signing id mismatch")
	}
	if err := validateRound1State(setup, state, "UnmarshalRound1Encrypted"); err != nil {
		return nil, err
	}
	return state, nil
}

// MarshalRound2Encrypted seals Protocol 3.6's round-2 state. Retaining this before
// choosing the message is pre-signing under the paper's Section 3.3 warning.
func MarshalRound2Encrypted(setup *SignerSetup, state *Round2State, enc SetupEncryptor) ([]byte, error) {
	if setup == nil {
		return nil, fmt.Errorf("dkls23 MarshalRound2Encrypted: missing setup")
	}
	setup.mu.RLock()
	defer setup.mu.RUnlock()
	if err := validateRound2State(setup, state, "MarshalRound2Encrypted"); err != nil {
		return nil, err
	}
	return sealRound(setup, state, state.SigID, 2, enc)
}

// UnmarshalRound2Encrypted restores the expected signing id's round-2 state.
func UnmarshalRound2Encrypted(setup *SignerSetup, operation string, ciphertext []byte, enc SetupEncryptor) (*Round2State, error) {
	b := setup.Binding()
	plaintext, err := envelope.Open(enc, stateContext(b, envelope.Sign2, operation, 2), ciphertext)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	var wire boundSigningJSON
	if err := statejson.Decode(plaintext, &wire); err != nil {
		return nil, err
	}
	if wire.Version != 1 || wire.Round2 == nil || wire.Round1 != nil || wire.Round2.Round1State == nil || wire.Round2.SigID != "" || string(wire.OperationID) != operation {
		return nil, fmt.Errorf("dkls23 UnmarshalRound2Encrypted: signing payload mismatch")
	}
	state := wire.Round2
	state.SigID = operation
	if setup == nil {
		return nil, fmt.Errorf("dkls23 UnmarshalRound2Encrypted: missing setup")
	}
	setup.mu.RLock()
	defer setup.mu.RUnlock()
	if state.Round1State == nil || state.SigID != operation {
		return nil, fmt.Errorf("dkls23 UnmarshalRound2Encrypted: signing id mismatch")
	}
	if err := validateRound2State(setup, state, "UnmarshalRound2Encrypted"); err != nil {
		return nil, err
	}
	return state, nil
}

func sealRound(setup *SignerSetup, state any, operation string, round int, enc SetupEncryptor) ([]byte, error) {
	wire := boundSigningJSON{Version: 1, OperationID: []byte(operation)}
	switch value := state.(type) {
	case *Round1State:
		snapshot := *value
		snapshot.SigID = ""
		wire.Round1 = &snapshot
	case *Round2State:
		snapshot := *value
		r1 := *value.Round1State
		r1.SigID = ""
		snapshot.Round1State = &r1
		wire.Round2 = &snapshot
	}
	plaintext, err := json.Marshal(wire)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	kind := envelope.Sign1
	if round == 2 {
		kind = envelope.Sign2
	}
	b := KeyBinding{PublicKey: setup.PubKey, PartyID: setup.MyID, Epoch: setup.Epoch}
	return envelope.Seal(enc, stateContext(b, kind, operation, round), plaintext)
}

// RefreshState holds one zero-constant refresh polynomial and its seed. Round is
// 1 or 2; this is local state encoding, not a change to the refresh protocol.
// Treat it as secret, use encrypted persistence, and erase it after finalization.
type RefreshState struct {
	Coefficients []btcec.ModNScalar
	Seed         [16]byte
	Round        int
}

type refreshStateJSON struct {
	Version      int      `json:"version"`
	Round        int      `json:"round"`
	Coefficients []string `json:"coefficients"`
	Seed         string   `json:"seed"`
}

// MarshalJSON encodes the private refresh state in the versioned local schema.
func (s *RefreshState) MarshalJSON() ([]byte, error) {
	if s.Round != 1 && s.Round != 2 {
		return nil, fmt.Errorf("dkls23 RefreshState: invalid round")
	}
	coeffs := make([]string, len(s.Coefficients))
	for i := range s.Coefficients {
		coeffs[i] = scalarToHex(&s.Coefficients[i])
	}
	return json.Marshal(refreshStateJSON{PrivateStateVersion, s.Round, coeffs, hex.EncodeToString(s.Seed[:])})
}

// UnmarshalJSON rejects malformed or noncanonical coefficients and preserves the
// receiver on every error. Polynomial size is checked against the key on import.
// Scalar decoding uses exact 32-byte input and rejects SetByteSlice overflow;
// source: secp256k1/v4 v4.4.1 modnscalar.go (fixed-width reduction/overflow flag).
func (s *RefreshState) UnmarshalJSON(data []byte) error {
	var j refreshStateJSON
	if err := statejson.Decode(data, &j); err != nil {
		return err
	}
	if j.Version != PrivateStateVersion || (j.Round != 1 && j.Round != 2) || j.Coefficients == nil {
		return fmt.Errorf("dkls23 RefreshState: invalid version, round or coefficients")
	}
	seed, err := decodeFixedHex("seed", j.Seed, 16)
	if err != nil {
		return err
	}
	defer clear(seed)
	next := RefreshState{Round: j.Round, Coefficients: make([]btcec.ModNScalar, len(j.Coefficients))}
	copy(next.Seed[:], seed)
	for i, c := range j.Coefficients {
		b, err := decodeFixedHex("coefficient", c, 32)
		if err != nil {
			return err
		}
		var scalar btcec.ModNScalar
		overflow := scalar.SetByteSlice(b)
		clear(b)
		if overflow {
			return fmt.Errorf("dkls23 RefreshState: noncanonical coefficient")
		}
		next.Coefficients[i] = scalar
	}
	*s = next
	return nil
}

// MarshalRefreshEncrypted seals one round of local private refresh state.
func MarshalRefreshEncrypted(signer *SignerSetup, operation string, state *RefreshState, enc SetupEncryptor) ([]byte, error) {
	if signer == nil || state == nil {
		return nil, fmt.Errorf("dkls23 MarshalRefreshEncrypted: missing state")
	}
	signer.mu.RLock()
	defer signer.mu.RUnlock()
	if err := validateSetupState(signer, "MarshalRefreshEncrypted"); err != nil {
		return nil, err
	}
	if len(state.Coefficients) != signer.Threshold-1 {
		return nil, fmt.Errorf("dkls23 MarshalRefreshEncrypted: incorrect polynomial size")
	}
	plaintext, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	b := KeyBinding{PublicKey: signer.PubKey, PartyID: signer.MyID, Epoch: signer.Epoch}
	return envelope.Seal(enc, stateContext(b, refreshKind(state.Round), operation, state.Round), plaintext)
}

// UnmarshalRefreshEncrypted restores the expected private refresh round.
func UnmarshalRefreshEncrypted(signer *SignerSetup, operation string, round int, ciphertext []byte, enc SetupEncryptor) (*RefreshState, error) {
	b := signer.Binding()
	plaintext, err := envelope.Open(enc, stateContext(b, refreshKind(round), operation, round), ciphertext)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	var state RefreshState
	if err := json.Unmarshal(plaintext, &state); err != nil {
		return nil, err
	}
	signer.mu.RLock()
	defer signer.mu.RUnlock()
	if err := validateSetupState(signer, "UnmarshalRefreshEncrypted"); err != nil {
		return nil, err
	}
	if state.Round != round {
		return nil, fmt.Errorf("dkls23 UnmarshalRefreshEncrypted: payload round mismatch")
	}
	if len(state.Coefficients) != signer.Threshold-1 {
		return nil, fmt.Errorf("dkls23 UnmarshalRefreshEncrypted: incorrect polynomial size")
	}
	return &state, nil
}

func refreshKind(round int) string {
	if round == 1 {
		return envelope.Refresh1
	}
	return envelope.Refresh2
}

func decodeFixedHex(field, value string, width int) ([]byte, error) {
	b, err := hex.DecodeString(value)
	if err != nil {
		return nil, err
	}
	if len(b) != width {
		clear(b)
		return nil, fmt.Errorf("dkls23: invalid %s width", field)
	}
	return b, nil
}

type boundSigningJSON struct {
	Version     int          `json:"version"`
	OperationID []byte       `json:"operation_id"`
	Round1      *Round1State `json:"round1"`
	Round2      *Round2State `json:"round2"`
}
