package frost

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"sync"
	"testing"

	"filippo.io/edwards25519"
	"github.com/chrisalmeida/go-mpc/envelope"
	"github.com/stretchr/testify/require"
)

type coldEncryptor struct{ aead cipher.AEAD }

func newColdEncryptor(t testing.TB) *coldEncryptor {
	t.Helper()
	var key [32]byte
	_, err := rand.Read(key[:])
	require.NoError(t, err)
	b, err := aes.NewCipher(key[:])
	require.NoError(t, err)
	a, err := cipher.NewGCMWithRandomNonce(b)
	require.NoError(t, err)
	return &coldEncryptor{a}
}
func (e *coldEncryptor) Encrypt(p []byte) ([]byte, error) { return e.aead.Seal(nil, nil, p, nil), nil }
func (e *coldEncryptor) Decrypt(c []byte) ([]byte, error) { return e.aead.Open(nil, nil, c, nil) }

func nonceFixture() *Round1State {
	d, e := scalarFromInt(1), scalarFromInt(2)
	pk := edwards25519.NewGeneratorPoint().Bytes()
	return &Round1State{Signers: []int{1}, HidingNonce: d, BindingNonce: e, Commitment: commitNonces(d, e), use: &nonceUse{id: 1, publicKey: string(pk), signers: []int{1}}}
}

func TestEncryptedNonceRestoreSingleUse(t *testing.T) {
	t.Parallel()
	for _, concurrent := range []bool{false, true} {
		t.Run(map[bool]string{false: "sequential", true: "concurrent"}[concurrent], func(t *testing.T) {
			states := makeSignerStates(fullSetup(t))
			enc := newColdEncryptor(t)
			signers := []int{1, 2, 3}
			commitments := make(map[int]*NonceCommitment)
			private := make(map[int]*Round1State)
			for _, id := range signers {
				state, c, err := SignRound1(states[id], signers)
				require.NoError(t, err)
				blob, err := MarshalRound1Encrypted(states[id], state, "portable", enc)
				require.NoError(t, err)
				restored, err := UnmarshalRound1Encrypted(states[id], "portable", blob, enc)
				require.NoError(t, err)
				private[id] = restored
				commitments[id] = c
			}
			copyState := *private[1]
			encoded, err := MarshalSignerEncrypted(states[1], enc)
			require.NoError(t, err)
			otherSigner, err := UnmarshalSignerEncrypted(encoded, enc, states[1].Binding())
			require.NoError(t, err)
			input := &Round2Input{Message: []byte("portable nonce pair"), AllCommitments: commitments}
			shares := make([]*SignatureShare, 2)
			errs := make([]error, 2)
			first := func() { shares[0], errs[0] = SignRound2(states[1], private[1], input) }
			second := func() { shares[1], errs[1] = SignRound2(otherSigner, &copyState, input) }
			if concurrent {
				var wg sync.WaitGroup
				wg.Add(2)
				go func() { defer wg.Done(); first() }()
				go func() { defer wg.Done(); second() }()
				wg.Wait()
			} else {
				first()
				second()
			}
			allShares := make(map[int]*SignatureShare)
			successes := 0
			for i, e := range errs {
				if e == nil {
					successes++
					allShares[1] = shares[i]
				}
			}
			require.Equal(t, 1, successes)
			for _, id := range []int{2, 3} {
				share, err := SignRound2(states[id], private[id], input)
				require.NoError(t, err)
				allShares[id] = share
			}
			ver := make(map[int][]byte)
			for id, s := range states {
				ver[id] = s.KeyShare.VerificationShare
			}
			sig, err := Aggregate(commitments, allShares, input.Message, states[1].KeyShare.PublicKey, ver, signers)
			require.NoError(t, err)
			require.True(t, ed25519.Verify(states[1].KeyShare.PublicKey, input.Message, sig.Bytes()))
			_, err = json.Marshal(private[1])
			require.Error(t, err)
		})
	}
}

func TestNonceUnmarshalErrorsPreserveReceiver(t *testing.T) {
	t.Parallel()
	valid, err := json.Marshal(nonceFixture())
	require.NoError(t, err)
	cases := map[string]string{"syntax": "{", "null": "null", "duplicate": string(valid[:len(valid)-1]) + `,"version":1}`, "trailing": string(valid) + ` {}`}
	changes := map[string]any{"version": 2, "public_key": "00", "party_id": 0, "epoch": -1, "signers": []int{2}, "hiding": "00", "binding": "00", "commitment": nil, "extra": true}
	for field, value := range changes {
		var doc map[string]any
		require.NoError(t, json.Unmarshal(valid, &doc))
		doc[field] = value
		b, err := json.Marshal(doc)
		require.NoError(t, err)
		cases[field] = string(b)
	}
	for _, field := range []string{"public_key", "hiding", "binding"} {
		for _, value := range []string{"gg", string(bytes.Repeat([]byte("ff"), 32))} {
			var doc map[string]any
			require.NoError(t, json.Unmarshal(valid, &doc))
			doc[field] = value
			b, err := json.Marshal(doc)
			require.NoError(t, err)
			cases[field+value] = string(b)
		}
	}
	var missing map[string]any
	require.NoError(t, json.Unmarshal(valid, &missing))
	delete(missing, "version")
	b, err := json.Marshal(missing)
	require.NoError(t, err)
	cases["missing"] = string(b)
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			state := nonceFixture()
			before, err := json.Marshal(state)
			require.NoError(t, err)
			require.Error(t, json.Unmarshal([]byte(input), state))
			after, err := json.Marshal(state)
			require.NoError(t, err)
			require.Equal(t, before, after)
		})
	}
	var doc map[string]any
	require.NoError(t, json.Unmarshal(valid, &doc))
	doc["commitment"] = commitNonces(scalarFromInt(2), scalarFromInt(1))
	bad, err := json.Marshal(doc)
	require.NoError(t, err)
	require.Error(t, json.Unmarshal(bad, nonceFixture()))
	_, err = json.Marshal(&Round1State{})
	require.Error(t, err)
	s := nonceFixture()
	s.Signers = []int{2}
	_, err = json.Marshal(s)
	require.Error(t, err)
}

func TestBoundSignerAndNonceRejectSubstitution(t *testing.T) {
	t.Parallel()
	states := makeSignerStates(fullSetup(t))
	signer := states[1]
	enc := newColdEncryptor(t)
	state, _, err := SignRound1(signer, []int{1, 2, 3})
	require.NoError(t, err)
	blob, err := MarshalRound1Encrypted(signer, state, "operation", enc)
	require.NoError(t, err)
	_, err = UnmarshalRound1Encrypted(signer, "different", blob, enc)
	require.Error(t, err)
	_, err = UnmarshalRound1Encrypted(states[2], "operation", blob, enc)
	require.Error(t, err)
	states[1].Epoch++
	_, err = UnmarshalRound1Encrypted(states[1], "operation", blob, enc)
	require.Error(t, err)
	states[1].Epoch--
	_, err = MarshalRound1Encrypted(states[2], state, "operation", enc)
	require.Error(t, err)
	for _, seal := range []func() ([]byte, error){func() ([]byte, error) { return MarshalEncrypted(signer.KeyShare, enc) }, func() ([]byte, error) { return MarshalSignerEncrypted(signer, enc) }} {
		encrypted, err := seal()
		require.NoError(t, err)
		context, err := envelope.Peek(encrypted)
		require.NoError(t, err)
		for _, mutate := range []func(*KeyBinding){func(b *KeyBinding) { b.PartyID = 2 }, func(b *KeyBinding) { b.Epoch++ }, func(b *KeyBinding) { b.PublicKey = states[2].KeyShare.VerificationShare }} {
			b := signer.Binding()
			mutate(&b)
			if context.Kind == envelope.Key {
				_, err = UnmarshalEncrypted(encrypted, enc, b)
			} else {
				_, err = UnmarshalSignerEncrypted(encrypted, enc, b)
			}
			require.Error(t, err)
		}
	}
	// Even a caller-authorized ciphertext must carry a matching payload binding.
	plaintext, err := MarshalSignerState(states[2])
	require.NoError(t, err)
	forged, err := envelope.Seal(enc, stateContext(signer.Binding(), envelope.Signer, "", 0), plaintext)
	require.NoError(t, err)
	_, err = UnmarshalSignerEncrypted(forged, enc, signer.Binding())
	require.Error(t, err)
	_, err = MarshalSignerEncrypted(nil, enc)
	require.Error(t, err)
	_, err = MarshalEncrypted(nil, enc)
	require.Error(t, err)
}

func FuzzUnmarshalRound1State(f *testing.F) {
	seed, _ := json.Marshal(nonceFixture())
	f.Add(seed)
	f.Add([]byte(`null`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		state := nonceFixture()
		before, err := json.Marshal(state)
		require.NoError(t, err)
		err = json.Unmarshal(data, state)
		after, marshalErr := json.Marshal(state)
		require.NoError(t, marshalErr)
		if err != nil {
			require.Equal(t, before, after)
		} else {
			var copy Round1State
			require.NoError(t, json.Unmarshal(after, &copy))
			again, err := json.Marshal(&copy)
			require.NoError(t, err)
			require.Equal(t, after, again)
		}
	})
}
