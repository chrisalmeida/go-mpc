package frost

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"

	"filippo.io/edwards25519"
	"github.com/chrisalmeida/go-mpc/envelope"
	"github.com/chrisalmeida/go-mpc/internal/statejson"
)

// PrivateStateVersion versions the new private nonce and refresh JSON schemas.
// It is independent of RFC 9591's public messages and existing key formats.
const PrivateStateVersion = 1

type nonceStateJSON struct {
	Version    int              `json:"version"`
	PublicKey  string           `json:"public_key"`
	PartyID    int              `json:"party_id"`
	Epoch      int              `json:"epoch"`
	Signers    []int            `json:"signers"`
	Hiding     string           `json:"hiding"`
	Binding    string           `json:"binding"`
	Commitment *NonceCommitment `json:"commitment"`
}

// MarshalJSON encodes RFC 9591 Section 5.1's unused private nonce pair and its
// local association. Plaintext is secret; use MarshalRound1Encrypted for storage.
// Copies in one process share the nonce-use lock. Restored copies require the
// authoritative session guard to prevent reuse across processes or backups.
func (s *Round1State) MarshalJSON() ([]byte, error) {
	if s == nil || s.use == nil {
		return nil, fmt.Errorf("frost Round1State: missing nonce binding")
	}
	s.use.mu.Lock()
	defer s.use.mu.Unlock()
	if s.consumed || s.use.consumed || s.HidingNonce == nil || s.BindingNonce == nil || !slices.Equal(s.Signers, s.use.signers) {
		return nil, fmt.Errorf("frost Round1State: consumed or corrupt nonces")
	}
	j := nonceStateJSON{Version: PrivateStateVersion, PublicKey: hex.EncodeToString([]byte(s.use.publicKey)), PartyID: s.use.id,
		Epoch: s.use.epoch, Signers: s.Signers, Hiding: hex.EncodeToString(s.HidingNonce.Bytes()),
		Binding: hex.EncodeToString(s.BindingNonce.Bytes()), Commitment: s.Commitment}
	if _, err := decodeNonceState(j); err != nil {
		return nil, err
	}
	return json.Marshal(j)
}

// UnmarshalJSON strictly restores a fresh local nonce-use record. It leaves the
// receiver unchanged on rejection. Importing the same bytes twice does not make
// them safe to use twice: use session progress for cross-restoration single use.
func (s *Round1State) UnmarshalJSON(data []byte) error {
	var j nonceStateJSON
	if err := statejson.Decode(data, &j); err != nil {
		return err
	}
	next, err := decodeNonceState(j)
	if err != nil {
		return err
	}
	*s = *next
	return nil
}

// decodeNonceState uses edwards25519 v1.2.0 scalar.go's fixed-width canonical
// check and the existing commitNonces operation. ScalarBaseMult in scalarmult.go
// uses fixed loops and tables.go SelectInto scans entries using masks. This is
// source evidence; it does not establish compiled timing on a deployment target.
func decodeNonceState(j nonceStateJSON) (*Round1State, error) {
	bad := func() (*Round1State, error) { return nil, fmt.Errorf("frost Round1State: invalid nonce state") }
	if j.Version != PrivateStateVersion || j.Epoch < 0 || j.PartyID < 1 || j.PartyID > maxPartyID {
		return bad()
	}
	if err := validatePartyIDs(j.Signers, "Round1State"); err != nil {
		return nil, err
	}
	if !slices.Contains(j.Signers, j.PartyID) {
		return bad()
	}
	pk, err := decodeFixedHex("public_key", j.PublicKey, ElementLen)
	if err != nil {
		return nil, err
	}
	if _, err := deserializeElement(pk); err != nil {
		return nil, err
	}
	hiding, err := decodeFixedHex("hiding", j.Hiding, ScalarLen)
	if err != nil {
		return nil, err
	}
	defer clear(hiding)
	binding, err := decodeFixedHex("binding", j.Binding, ScalarLen)
	if err != nil {
		return nil, err
	}
	defer clear(binding)
	d, err := edwards25519.NewScalar().SetCanonicalBytes(hiding)
	if err != nil {
		return nil, err
	}
	e, err := edwards25519.NewScalar().SetCanonicalBytes(binding)
	if err != nil {
		return nil, err
	}
	if j.Commitment == nil {
		return bad()
	}
	if _, err := deserializeElement(j.Commitment.HidingNonceCommitment); err != nil {
		return nil, err
	}
	if _, err := deserializeElement(j.Commitment.BindingNonceCommitment); err != nil {
		return nil, err
	}
	actual := commitNonces(d, e)
	if subtle.ConstantTimeCompare(actual.HidingNonceCommitment, j.Commitment.HidingNonceCommitment) != 1 ||
		subtle.ConstantTimeCompare(actual.BindingNonceCommitment, j.Commitment.BindingNonceCommitment) != 1 {
		return bad()
	}
	return &Round1State{Signers: slices.Clone(j.Signers), HidingNonce: d, BindingNonce: e, Commitment: j.Commitment,
		use: &nonceUse{id: j.PartyID, epoch: j.Epoch, publicKey: string(pk), signers: slices.Clone(j.Signers)}}, nil
}

// MarshalRound1Encrypted seals RFC 9591's unused nonce pair for one operation.
func MarshalRound1Encrypted(signer *SignerState, state *Round1State, operation string, enc SetupEncryptor) ([]byte, error) {
	b := signer.Binding()
	plaintext, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	// Decode a private snapshot so serialization and validation see the same state.
	var snapshot Round1State
	if err := json.Unmarshal(plaintext, &snapshot); err != nil {
		return nil, err
	}
	if err := matchNonceBinding(&snapshot, b); err != nil {
		return nil, err
	}
	return envelope.Seal(enc, stateContext(b, envelope.Sign1, operation, 1), plaintext)
}

// UnmarshalRound1Encrypted restores an unused nonce pair for the trusted signer
// and operation. The session guard must still enforce one use of the checkpoint.
func UnmarshalRound1Encrypted(signer *SignerState, operation string, ciphertext []byte, enc SetupEncryptor) (*Round1State, error) {
	b := signer.Binding()
	plaintext, err := envelope.Open(enc, stateContext(b, envelope.Sign1, operation, 1), ciphertext)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	var state Round1State
	if err := json.Unmarshal(plaintext, &state); err != nil {
		return nil, err
	}
	if err := matchNonceBinding(&state, b); err != nil {
		return nil, err
	}
	signer.mu.RLock()
	defer signer.mu.RUnlock()
	if err := validateSigningState(signer, state.Signers, "UnmarshalRound1Encrypted"); err != nil {
		return nil, err
	}
	return &state, nil
}

func matchNonceBinding(s *Round1State, b KeyBinding) error {
	if s.use == nil || s.use.id != b.PartyID || s.use.epoch != b.Epoch || s.use.publicKey != string(b.PublicKey) {
		return &CorruptStateError{Phase: "Round1State", Detail: "nonce binding differs from signer"}
	}
	return nil
}

// RefreshState holds one zero-constant refresh polynomial and its seed. Round is
// 1 or 2; this is local state encoding, not a change to the refresh protocol.
// Treat it as secret, use encrypted persistence, and erase it after finalization.
type RefreshState struct {
	Coefficients []*edwards25519.Scalar
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
		return nil, fmt.Errorf("frost RefreshState: invalid round")
	}
	coeffs := make([]string, len(s.Coefficients))
	for i, c := range s.Coefficients {
		if c == nil {
			return nil, fmt.Errorf("frost RefreshState: missing coefficient")
		}
		coeffs[i] = hex.EncodeToString(c.Bytes())
	}
	return json.Marshal(refreshStateJSON{PrivateStateVersion, s.Round, coeffs, hex.EncodeToString(s.Seed[:])})
}

// UnmarshalJSON rejects malformed or noncanonical coefficients and preserves the
// receiver on every error. Polynomial size is checked against the key on import.
func (s *RefreshState) UnmarshalJSON(data []byte) error {
	var j refreshStateJSON
	if err := statejson.Decode(data, &j); err != nil {
		return err
	}
	if j.Version != PrivateStateVersion || (j.Round != 1 && j.Round != 2) || j.Coefficients == nil {
		return fmt.Errorf("frost RefreshState: invalid version, round or coefficients")
	}
	seed, err := decodeFixedHex("seed", j.Seed, 16)
	if err != nil {
		return err
	}
	defer clear(seed)
	next := RefreshState{Round: j.Round, Coefficients: make([]*edwards25519.Scalar, len(j.Coefficients))}
	copy(next.Seed[:], seed)
	for i, c := range j.Coefficients {
		b, err := decodeFixedHex("coefficient", c, ScalarLen)
		if err != nil {
			return err
		}
		scalar, err := edwards25519.NewScalar().SetCanonicalBytes(b)
		clear(b)
		if err != nil {
			return err
		}
		next.Coefficients[i] = scalar
	}
	*s = next
	return nil
}

// MarshalRefreshEncrypted seals one round of local private refresh state.
func MarshalRefreshEncrypted(signer *SignerState, operation string, state *RefreshState, enc SetupEncryptor) ([]byte, error) {
	if signer == nil || state == nil {
		return nil, fmt.Errorf("frost MarshalRefreshEncrypted: missing state")
	}
	signer.mu.RLock()
	defer signer.mu.RUnlock()
	if err := validateSignerState(signer, "MarshalRefreshEncrypted"); err != nil {
		return nil, err
	}
	if err := validateRefreshCoefficients(state.Coefficients, signer.KeyShare.Threshold, "MarshalRefreshEncrypted"); err != nil {
		return nil, err
	}
	plaintext, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	b := KeyBinding{PublicKey: signer.KeyShare.PublicKey, PartyID: signer.KeyShare.ID, Epoch: signer.Epoch}
	return envelope.Seal(enc, stateContext(b, refreshKind(state.Round), operation, state.Round), plaintext)
}

// UnmarshalRefreshEncrypted restores the expected private refresh round.
func UnmarshalRefreshEncrypted(signer *SignerState, operation string, round int, ciphertext []byte, enc SetupEncryptor) (*RefreshState, error) {
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
	if err := validateSignerState(signer, "UnmarshalRefreshEncrypted"); err != nil {
		return nil, err
	}
	if state.Round != round {
		return nil, fmt.Errorf("frost UnmarshalRefreshEncrypted: payload round mismatch")
	}
	if err := validateRefreshCoefficients(state.Coefficients, signer.KeyShare.Threshold, "UnmarshalRefreshEncrypted"); err != nil {
		return nil, err
	}
	return &state, nil
}

func refreshKind(round int) string {
	if round == 1 {
		return envelope.Refresh1
	}
	return envelope.Refresh2
}
