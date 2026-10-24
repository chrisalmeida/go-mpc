package dkls23

import (
	"encoding/json"
	"testing"

	"github.com/chrisalmeida/go-mpc/envelope"
	"github.com/chrisalmeida/go-mpc/session"
	"github.com/stretchr/testify/require"
)

func TestBoundSetupRejectsLegacyAndMismatchedOrNoncanonicalPayload(t *testing.T) {
	t.Parallel()
	setup := fullSetup(t)[1]
	enc := newTestEncryptor()
	binding := setup.Binding()
	blob, err := MarshalEncrypted(setup, enc)
	require.NoError(t, err)
	context := stateContext(binding, envelope.Setup, "", 0)
	plaintext, err := envelope.Open(enc, context, blob)
	require.NoError(t, err)
	for name, change := range map[string]func(*boundSetupJSON){
		"payload version": func(w *boundSetupJSON) { w.Version = 2 }, "missing setup": func(w *boundSetupJSON) { w.Setup = nil }, "missing sessions": func(w *boundSetupJSON) { w.SessionIDs = nil },
		"nested sessions": func(w *boundSetupJSON) { w.Setup.SessionIDs = map[string]int{"old": 1} }, "bad session encoding": func(w *boundSetupJSON) { w.SessionIDs["!"] = 1 }, "empty session": func(w *boundSetupJSON) { w.SessionIDs[""] = 1 }, "bad progress": func(w *boundSetupJSON) { w.SessionIDs["c2lnbg"] = 4 },
		"wrong party": func(w *boundSetupJSON) { w.Setup.MyID = 2 }, "wrong epoch": func(w *boundSetupJSON) { w.Setup.Epoch++ }, "bad key": func(w *boundSetupJSON) { w.Setup.PubKey = nil },
	} {
		t.Run(name, func(t *testing.T) {
			var wire boundSetupJSON
			require.NoError(t, json.Unmarshal(plaintext, &wire))
			change(&wire)
			data, err := json.Marshal(wire)
			require.NoError(t, err)
			forged, err := envelope.Seal(enc, context, data)
			require.NoError(t, err)
			got, err := UnmarshalEncrypted(forged, enc, binding)
			require.Error(t, err)
			require.Nil(t, got)
		})
	}
	// The bound path rejects a scalar the legacy parser would silently reduce.
	var doc map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(plaintext, &doc))
	var nested map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(doc["setup"], &nested))
	nested["share"] = json.RawMessage(`"01"`)
	doc["setup"], err = json.Marshal(nested)
	require.NoError(t, err)
	data, err := json.Marshal(doc)
	require.NoError(t, err)
	forged, err := envelope.Seal(enc, context, data)
	require.NoError(t, err)
	_, err = UnmarshalEncrypted(forged, enc, binding)
	require.Error(t, err)
	legacy, err := MarshalSetup(setup)
	require.NoError(t, err)
	legacy, err = enc.Encrypt(legacy)
	require.NoError(t, err)
	_, err = UnmarshalEncrypted(legacy, enc, binding)
	require.Error(t, err)
	for _, mutate := range []func(*KeyBinding){func(b *KeyBinding) { b.PartyID++ }, func(b *KeyBinding) { b.Epoch++ }, func(b *KeyBinding) { b.PublicKey[2] ^= 1 }} {
		expect := setup.Binding()
		mutate(&expect)
		_, err = UnmarshalEncrypted(blob, enc, expect)
		require.Error(t, err)
	}
	_, err = MarshalEncrypted(nil, enc)
	require.Error(t, err)
	_, err = MarshalSetup(nil)
	require.Error(t, err)
	var missing *SignerSetup
	require.Empty(t, missing.Binding().PublicKey)
}

func TestBoundSigningStateRejectsPayloadAndOperationSubstitution(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	s := runRound1(t, setups, t.Name(), []int{1, 2, 3})
	runRound2(t, setups, s)
	enc := newTestEncryptor()
	setup := setups[1]
	r1, err := MarshalRound1Encrypted(setup, s.r2States[1].Round1State, enc)
	require.NoError(t, err)
	r2, err := MarshalRound2Encrypted(setup, s.r2States[1], enc)
	require.NoError(t, err)
	_, err = UnmarshalRound1Encrypted(setup, "other", r1, enc)
	require.Error(t, err)
	_, err = UnmarshalRound2Encrypted(setup, "other", r2, enc)
	require.Error(t, err)
	_, err = UnmarshalRound1Encrypted(setups[2], s.sigID, r1, enc)
	require.Error(t, err)
	_, err = UnmarshalRound2Encrypted(setups[2], s.sigID, r2, enc)
	require.Error(t, err)
	for round, blob := range map[int][]byte{1: r1, 2: r2} {
		kind := envelope.Sign1
		if round == 2 {
			kind = envelope.Sign2
		}
		context := stateContext(setup.Binding(), kind, s.sigID, round)
		plain, err := envelope.Open(enc, context, blob)
		require.NoError(t, err)
		for _, change := range []func(*boundSigningJSON){func(w *boundSigningJSON) { w.Version = 2 }, func(w *boundSigningJSON) { w.OperationID = []byte("foreign") }, func(w *boundSigningJSON) { w.Round1 = nil; w.Round2 = nil }, func(w *boundSigningJSON) {
			if w.Round1 != nil {
				one := scalarOneForCold()
				w.Round1.ZetaI.Add(&one)
			} else {
				one := scalarOneForCold()
				w.Round2.SK_i.Add(&one)
			}
		}} {
			var w boundSigningJSON
			require.NoError(t, json.Unmarshal(plain, &w))
			change(&w)
			p, err := json.Marshal(w)
			require.NoError(t, err)
			forged, err := envelope.Seal(enc, context, p)
			require.NoError(t, err)
			if round == 1 {
				got, err := UnmarshalRound1Encrypted(setup, s.sigID, forged, enc)
				require.Error(t, err)
				require.Nil(t, got)
			} else {
				got, err := UnmarshalRound2Encrypted(setup, s.sigID, forged, enc)
				require.Error(t, err)
				require.Nil(t, got)
			}
		}
	}
	_, err = MarshalRound1Encrypted(nil, nil, enc)
	require.Error(t, err)
	_, err = MarshalRound2Encrypted(nil, nil, enc)
	require.Error(t, err)
	_, err = MarshalRound1Encrypted(setup, nil, enc)
	require.Error(t, err)
	_, err = MarshalRound2Encrypted(setup, nil, enc)
	require.Error(t, err)
}

func TestSessionCodecRequiresExplicitPreSigningOptIn(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	parties := []int{1, 2, 3}
	s := runRound1(t, setups, t.Name(), parties)
	enc := newTestEncryptor()
	codec := SessionCodec{enc}
	key, err := MarshalEncrypted(setups[1], enc)
	require.NoError(t, err)
	checkpoint, err := MarshalRound1Encrypted(setups[1], s.r1States[1], enc)
	require.NoError(t, err)
	in := session.Input{Scope: session.Scope{Protocol: session.DKLS23, PublicKey: string(setups[1].PubKey), PartyID: 1}, Request: session.Request{Version: session.Version{Revision: 1}, ID: session.ID{Kind: session.Signing, Value: s.sigID}, Round: 2, Participants: parties}, KeyCheckpoint: key, SessionCheckpoint: checkpoint}
	input := SessionSignInput{Round1: s.round1For(1)}
	rejected, err := codec.Signing(input)(in)
	require.ErrorIs(t, err, session.ErrInvalid)
	require.Empty(t, rejected.Output)
	input.AllowPreSigning = true
	u, err := codec.Signing(input)(in)
	require.NoError(t, err)
	setups[1], err = UnmarshalEncrypted(u.KeyCheckpoint, enc, setups[1].Binding())
	require.NoError(t, err)
	restored, err := UnmarshalRound2Encrypted(setups[1], s.sigID, u.Checkpoint, enc)
	require.NoError(t, err)
	output, err := codec.OpenOutput(u.Output, setups[1].Binding(), in.ID, 2)
	require.NoError(t, err)
	s.r2States = map[int]*Round2State{1: restored}
	s.r2Msgs = make(map[int]map[int]*Round2Msg)
	var outbound map[int]*Round2Msg
	require.NoError(t, json.Unmarshal(output, &outbound))
	s.r2Msgs[1] = outbound
	for _, id := range []int{2, 3} {
		state, msgs, err := SignRound2(setups[id], s.r1States[id], s.round1For(id))
		require.NoError(t, err)
		s.r2States[id] = state
		s.r2Msgs[id] = msgs
	}
	message := []byte("chosen after the explicit opt-in round 2")
	runRound3(t, setups, s, message)
	r, ss := s.combine(t, setups, message)
	verifyECDSA(t, setups[1].PubKey, message, r, ss)
}
