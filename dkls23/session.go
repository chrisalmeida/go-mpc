package dkls23

import (
	"encoding/json"
	"errors"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/chrisalmeida/go-mpc/envelope"
	"github.com/chrisalmeida/go-mpc/internal/statejson"
	"slices"

	"github.com/chrisalmeida/go-mpc/session"
)

// SessionCodec encodes DKLS23 Protocol 3.6 signing and KMOS21 refresh callbacks
// for session.Advance. Every invocation restores fresh, bound encrypted
// authoritative state. The application supplies authenticated peer routing,
// storage, authenticated encryption and group-coordinated refresh activation.
type SessionCodec struct{ Encryptor SetupEncryptor }

// SessionSignInput supplies authenticated inbound peer messages for the next
// round. Message is used cryptographically only in round 3. Supply a non-nil
// message in round 2, or explicitly accept paper Section 3.3's stronger assumption
// by setting AllowPreSigning. A nil message in round 3 is the empty message.
type SessionSignInput struct {
	Round1          map[int]*Round1Msg
	Round2          map[int]*Round2Msg
	Message         []byte
	AllowPreSigning bool
}

func (c SessionCodec) restore(in session.Input) (*SignerSetup, error) {
	if in.Scope.Protocol != session.DKLS23 || in.Epoch != in.ID.Epoch {
		return nil, session.ErrInvalid
	}
	return UnmarshalEncrypted(in.KeyCheckpoint, c.Encryptor, KeyBinding{PublicKey: []byte(in.Scope.PublicKey), PartyID: in.Scope.PartyID, Epoch: in.Epoch})
}

// Signing returns one protocol round as a storage callback. OpenOutput decrypts
// its committed output to a JSON map keyed by recipient id, including the self
// entry in round 3. Never transmit
// outputs inside the transaction; send only Receipt.Output or session.Output.
func (c SessionCodec) Signing(input SessionSignInput) session.Compute {
	return func(in session.Input) (session.Update, error) {
		var u session.Update
		if in.ID.Kind != session.Signing {
			return u, session.ErrInvalid
		}
		setup, err := c.restore(in)
		if err != nil {
			return u, err
		}
		if err := validateSigningSetup(setup, in.Participants, "SessionCodec.Signing"); err != nil {
			return u, err
		}
		switch in.Round {
		case 1:
			if len(in.SessionCheckpoint) != 0 {
				return u, session.ErrCorrupt
			}
			state, out, err := SignRound1(setup, in.ID.Value, in.Participants)
			if err != nil {
				return c.protocolError(setup, err)
			}
			defer eraseRound1(state)
			u.Checkpoint, err = MarshalRound1Encrypted(setup, state, c.Encryptor)
			if err != nil {
				return u, err
			}
			u.NonceID = string(state.R_iPoint)
			u.Output, err = json.Marshal(out)
			if err != nil {
				return u, err
			}
		case 2:
			if input.Message == nil && !input.AllowPreSigning {
				return u, session.ErrInvalid
			}
			state, err := UnmarshalRound1Encrypted(setup, in.ID.Value, in.SessionCheckpoint, c.Encryptor)
			if err != nil {
				return u, err
			}
			defer eraseRound1(state)
			if !sameParties(state.Signers, in.Participants) {
				return u, session.ErrInvalid
			}
			state2, out, err := SignRound2(setup, state, input.Round1)
			if err != nil {
				return c.protocolError(setup, err)
			}
			defer eraseRound2(state2)
			u.Checkpoint, err = MarshalRound2Encrypted(setup, state2, c.Encryptor)
			if err != nil {
				return u, err
			}
			u.Output, err = json.Marshal(out)
			if err != nil {
				return u, err
			}
		case 3:
			state, err := UnmarshalRound2Encrypted(setup, in.ID.Value, in.SessionCheckpoint, c.Encryptor)
			if err != nil {
				return u, err
			}
			defer eraseRound2(state)
			if !sameParties(state.Signers, in.Participants) {
				return u, session.ErrInvalid
			}
			out, err := SignRound3(setup, state, input.Message, input.Round2)
			if err != nil {
				return c.protocolError(setup, err)
			}
			u.Output, err = json.Marshal(out)
			if err != nil {
				return u, err
			}
		default:
			return u, session.ErrInvalid
		}
		u.Output, err = sealOutput(u.Output, setup.Binding(), in.ID.Value, envelope.SignOutput, in.Round, c.Encryptor)
		if err != nil {
			return u, err
		}
		u.KeyCheckpoint, err = MarshalEncrypted(setup, c.Encryptor)
		return u, err
	}
}

func (c SessionCodec) protocolError(setup *SignerSetup, cause error) (session.Update, error) {
	var cheating *CheatingPartyError
	if !errors.As(cause, &cheating) {
		return session.Update{}, cause
	}
	checkpoint, err := MarshalEncrypted(setup, c.Encryptor)
	if err != nil {
		return session.Update{}, err
	}
	var blacklist []int
	for id, bad := range setup.Blacklist {
		if bad {
			blacklist = append(blacklist, id)
		}
	}
	return session.Update{KeyCheckpoint: checkpoint, Blacklist: blacklist, Abort: cause}, nil
}

// Refresh returns a callback for the three local refresh rounds. Participants
// must be the entire configured group. The final round prepares epoch+1 state;
// the caller coordinates the group before calling session.Activate.
func (c SessionCodec) Refresh(round1 map[int]*RefreshRound1Output, round2 map[int]*RefreshRound2Output) session.Compute {
	return func(in session.Input) (session.Update, error) {
		var u session.Update
		if in.ID.Kind != session.Refresh {
			return u, session.ErrInvalid
		}
		setup, err := c.restore(in)
		if err != nil {
			return u, err
		}
		if !sameParties(setup.AllIDs, in.Participants) {
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
			output, coeffs, seed, err := RefreshRound1(setup)
			if err != nil {
				return c.protocolError(setup, err)
			}
			state = &RefreshState{Round: 1, Coefficients: coeffs, Seed: seed}
			u.Output, err = json.Marshal(output)
			if err != nil {
				return u, err
			}
		} else {
			state, err = UnmarshalRefreshEncrypted(setup, in.ID.Value, in.Round-1, in.SessionCheckpoint, c.Encryptor)
			if err != nil {
				return u, err
			}
			if in.Round == 2 {
				output, err := RefreshRound2(setup, state.Coefficients, state.Seed)
				if err != nil {
					return c.protocolError(setup, err)
				}
				state.Round = 2
				u.Output, err = sealRefreshOutput(output, setup.Binding(), in.ID.Value, c.Encryptor)
				if err != nil {
					return u, err
				}
			} else if in.Round == 3 {
				if err := RefreshFinalize(setup, state.Coefficients, state.Seed, round1, round2); err != nil {
					return c.protocolError(setup, err)
				}
			} else {
				return u, session.ErrInvalid
			}
		}
		if in.Round < 3 {
			u.Checkpoint, err = MarshalRefreshEncrypted(setup, in.ID.Value, state, c.Encryptor)
			if err != nil {
				return u, err
			}
		}
		if in.Round == 1 {
			u.Output, err = sealOutput(u.Output, setup.Binding(), in.ID.Value, envelope.RefreshOutput, 1, c.Encryptor)
			if err != nil {
				return u, err
			}
		}
		u.KeyCheckpoint, err = MarshalEncrypted(setup, c.Encryptor)
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
func eraseRound1(s *Round1State) {
	s.R_i.Zero()
	s.Phi_i.Zero()
	s.ZetaI.Zero()
	for _, b := range s.VoleBobForRound2 {
		if b != nil {
			b.Chi.Zero()
			clear(b.Beta[:])
			clear(b.Gamma)
		}
	}
}
func eraseRound2(s *Round2State) {
	eraseRound1(s.Round1State)
	s.SK_i.Zero()
	for id, c := range s.C_u {
		c.Zero()
		s.C_u[id] = c
	}
	for id, c := range s.C_v {
		c.Zero()
		s.C_v[id] = c
	}
}
func (s *RefreshState) erase() {
	for i := range s.Coefficients {
		s.Coefficients[i].Zero()
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
		var scalar btcec.ModNScalar
		overflow := scalar.SetByteSlice(share)
		scalar.Zero()
		if overflow {
			return nil, session.ErrCorrupt
		}
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
