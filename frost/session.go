package frost

import (
	"encoding/json"
	"filippo.io/edwards25519"
	"github.com/chrisalmeida/go-mpc/envelope"
	"github.com/chrisalmeida/go-mpc/internal/statejson"
	"slices"

	"github.com/chrisalmeida/go-mpc/session"
)

// SessionCodec encodes RFC 9591 signing and refresh rounds for session.Advance.
// Each callback restores fresh, context-bound encrypted authoritative checkpoints.
// Encryptor must authenticate ciphertext. Caller supplies authenticated peer
// routing, an authoritative Store and group-coordinated refresh activation.
type SessionCodec struct{ Encryptor SetupEncryptor }

func (c SessionCodec) restore(in session.Input) (*SignerState, error) {
	if in.Scope.Protocol != session.FROST || in.Epoch != in.ID.Epoch {
		return nil, session.ErrInvalid
	}
	return UnmarshalSignerEncrypted(in.KeyCheckpoint, c.Encryptor, KeyBinding{PublicKey: []byte(in.Scope.PublicKey), PartyID: in.Scope.PartyID, Epoch: in.Epoch})
}

// Signing returns a callback for RFC 9591's two signing rounds. Round 1 ignores
// input; round 2 uses the exact message and commitment list provided by the caller.
// OpenOutput decrypts committed output to NonceCommitment (round 1) or
// SignatureShare (round 2) JSON.
func (c SessionCodec) Signing(input *Round2Input) session.Compute {
	return func(in session.Input) (session.Update, error) {
		var u session.Update
		if in.ID.Kind != session.Signing {
			return u, session.ErrInvalid
		}
		signer, err := c.restore(in)
		if err != nil {
			return u, err
		}
		if err := validateSigningState(signer, in.Participants, "SessionCodec.Signing"); err != nil {
			return u, err
		}
		switch in.Round {
		case 1:
			if len(in.SessionCheckpoint) != 0 {
				return u, session.ErrCorrupt
			}
			state, commitment, err := SignRound1(signer, in.Participants)
			if err != nil {
				return u, err
			}
			defer eraseNonces(state)
			u.Checkpoint, err = MarshalRound1Encrypted(signer, state, in.ID.Value, c.Encryptor)
			if err != nil {
				return u, err
			}
			u.Output, err = json.Marshal(commitment)
			if err != nil {
				return u, err
			}
			u.NonceID = string(append(slices.Clone(commitment.HidingNonceCommitment), commitment.BindingNonceCommitment...))
		case 2:
			state, err := UnmarshalRound1Encrypted(signer, in.ID.Value, in.SessionCheckpoint, c.Encryptor)
			if err != nil {
				return u, err
			}
			defer eraseNonces(state)
			if !sameParties(state.Signers, in.Participants) {
				return u, session.ErrInvalid
			}
			share, err := SignRound2(signer, state, input)
			if err != nil {
				return u, err
			}
			u.Output, err = json.Marshal(share)
			if err != nil {
				return u, err
			}
		default:
			return u, session.ErrInvalid
		}
		u.Output, err = sealOutput(u.Output, signer.Binding(), in.ID.Value, envelope.SignOutput, in.Round, c.Encryptor)
		if err != nil {
			return u, err
		}
		u.KeyCheckpoint, err = MarshalSignerEncrypted(signer, c.Encryptor)
		return u, err
	}
}

// Refresh returns a callback for the zero-constant refresh rounds. The final
// callback prepares an epoch+1 key; session.Activate is a separate coordinated
// application action. Participants must be the complete configured group.
func (c SessionCodec) Refresh(round1 map[int]*RefreshRound1Output, round2 map[int]*RefreshRound2Output) session.Compute {
	return func(in session.Input) (session.Update, error) {
		var u session.Update
		if in.ID.Kind != session.Refresh {
			return u, session.ErrInvalid
		}
		signer, err := c.restore(in)
		if err != nil {
			return u, err
		}
		if !sameParties(signer.KeyShare.AllIDs, in.Participants) {
			return u, session.ErrInvalid
		}
		var state *RefreshState
		defer func() {
			if state != nil {
				state.erase()
			}
		}()
		if in.Round == 1 {
			if len(in.SessionCheckpoint) != 0 {
				return u, session.ErrCorrupt
			}
			output, coeffs, seed, err := RefreshRound1(signer)
			if err != nil {
				return u, err
			}
			state = &RefreshState{Round: 1, Coefficients: coeffs, Seed: seed}
			u.Output, err = json.Marshal(output)
			if err != nil {
				return u, err
			}
		} else {
			state, err = UnmarshalRefreshEncrypted(signer, in.ID.Value, in.Round-1, in.SessionCheckpoint, c.Encryptor)
			if err != nil {
				return u, err
			}
			if in.Round == 2 {
				output, err := RefreshRound2(signer, state.Coefficients, state.Seed)
				if err != nil {
					return u, err
				}
				state.Round = 2
				u.Output, err = sealRefreshOutput(output, signer.Binding(), in.ID.Value, c.Encryptor)
				if err != nil {
					return u, err
				}
			} else if in.Round == 3 {
				if err := RefreshFinalize(signer, state.Coefficients, state.Seed, round1, round2); err != nil {
					return u, err
				}
			} else {
				return u, session.ErrInvalid
			}
		}
		if in.Round < 3 {
			u.Checkpoint, err = MarshalRefreshEncrypted(signer, in.ID.Value, state, c.Encryptor)
			if err != nil {
				return u, err
			}
		}
		if in.Round == 1 {
			u.Output, err = sealOutput(u.Output, signer.Binding(), in.ID.Value, envelope.RefreshOutput, 1, c.Encryptor)
			if err != nil {
				return u, err
			}
		}
		u.KeyCheckpoint, err = MarshalSignerEncrypted(signer, c.Encryptor)
		return u, err
	}
}

func sameParties(a, b []int) bool {
	a = slices.Clone(a)
	b = slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}
func eraseNonces(state *Round1State) {
	if state.HidingNonce != nil {
		state.HidingNonce.Set(edwards25519.NewScalar())
	}
	if state.BindingNonce != nil {
		state.BindingNonce.Set(edwards25519.NewScalar())
	}
}
func (s *RefreshState) erase() {
	for _, c := range s.Coefficients {
		c.Set(edwards25519.NewScalar())
	}
	clear(s.Seed[:])
}

// OpenRefreshRound2 opens a cached, encrypted round-2 refresh message for its
// trusted sender binding and operation. This message contains secret peer shares.
// Decrypt only after confirmed
// commit, then route each share over its authenticated confidential channel.
func (c SessionCodec) OpenRefreshRound2(blob []byte, expect KeyBinding, operation string) (*RefreshRound2Output, error) {
	plaintext, err := c.OpenOutput(blob, expect, session.ID{Kind: session.Refresh, Epoch: expect.Epoch, Value: operation}, 2)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	var output RefreshRound2Output
	if err := statejson.Decode(plaintext, &output); err != nil {
		return nil, err
	}
	if output.SecretShares == nil {
		return nil, session.ErrCorrupt
	}
	for id, share := range output.SecretShares {
		if id < 1 || id > maxPartyID || id == expect.PartyID || len(share) != 32 {
			return nil, session.ErrCorrupt
		}
		scalar, err := edwards25519.NewScalar().SetCanonicalBytes(share)
		if err != nil {
			return nil, err
		}
		scalar.Set(edwards25519.NewScalar())
	}
	return &output, nil
}

func sealRefreshOutput(output *RefreshRound2Output, binding KeyBinding, operation string, enc SetupEncryptor) ([]byte, error) {
	defer func() {
		for _, share := range output.SecretShares {
			clear(share)
		}
	}()
	plaintext, err := json.Marshal(output)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	return envelope.Seal(enc, stateContext(binding, envelope.RefreshOutput, operation, 2), plaintext)
}

// OpenOutput decrypts committed outbound bytes for their trusted sender, operation
// and round. Decode and validate the returned protocol message before use; this
// function provides association and at-rest confidentiality, not peer transport
// authentication. Cached outputs in Store remain ciphertext for every round.
func (c SessionCodec) OpenOutput(blob []byte, expect KeyBinding, id session.ID, round int) ([]byte, error) {
	if id.Epoch != expect.Epoch {
		return nil, session.ErrInvalid
	}
	kind := envelope.SignOutput
	if id.Kind == session.Refresh {
		kind = envelope.RefreshOutput
	} else if id.Kind != session.Signing {
		return nil, session.ErrInvalid
	}
	return envelope.Open(c.Encryptor, stateContext(expect, kind, id.Value, round), blob)
}
func sealOutput(plaintext []byte, b KeyBinding, operation, kind string, round int, enc SetupEncryptor) ([]byte, error) {
	defer clear(plaintext)
	return envelope.Seal(enc, stateContext(b, kind, operation, round), plaintext)
}
