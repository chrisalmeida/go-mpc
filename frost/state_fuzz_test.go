package frost

import (
	"encoding/json"
	"filippo.io/edwards25519"
	"github.com/chrisalmeida/go-mpc/envelope"
	"github.com/stretchr/testify/require"
	"testing"
)

func FuzzUnmarshalEncryptedPrivateState(f *testing.F) {
	signer := NewSignerState(&KeyShare{ID: 1, AllIDs: []int{1}, Threshold: 1, PublicKey: edwards25519.NewGeneratorPoint().Bytes(), SecretShare: scalarFromInt(1).Bytes()})
	enc := newColdEncryptor(f)
	binding := signer.Binding()
	keyPayload, err := MarshalKeyShare(signer.KeyShare)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(uint8(0), keyPayload)
	signerPayload, err := MarshalSignerState(signer)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(uint8(1), signerPayload)
	noncePayload, err := json.Marshal(nonceFixture())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(uint8(2), noncePayload)
	for _, round := range []int{1, 2} {
		seed, err := json.Marshal(&RefreshState{Round: round})
		if err != nil {
			f.Fatal(err)
		}
		f.Add(uint8(round+2), seed)
	}
	outbound, err := json.Marshal(&RefreshRound2Output{SecretShares: map[int][]byte{}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(uint8(5), outbound)
	f.Fuzz(func(t *testing.T, choice uint8, payload []byte) {
		choice %= 6
		kinds := []string{envelope.Key, envelope.Signer, envelope.Sign1, envelope.Refresh1, envelope.Refresh2, envelope.RefreshOutput}
		round := 0
		if choice == 2 || choice == 3 {
			round = 1
		}
		if choice == 4 || choice == 5 {
			round = 2
		}
		operation := ""
		if round > 0 {
			operation = "operation"
		}
		blob, err := envelope.Seal(enc, stateContext(binding, kinds[choice], operation, round), payload)
		require.NoError(t, err)
		switch choice {
		case 0:
			value, err := UnmarshalEncrypted(blob, enc, binding)
			if err != nil {
				require.Nil(t, value)
			}
		case 1:
			value, err := UnmarshalSignerEncrypted(blob, enc, binding)
			if err != nil {
				require.Nil(t, value)
			}
		case 2:
			value, err := UnmarshalRound1Encrypted(signer, "operation", blob, enc)
			if err != nil {
				require.Nil(t, value)
			}
		case 5:
			value, err := (SessionCodec{enc}).OpenRefreshRound2(blob, binding, "operation")
			if err != nil {
				require.Nil(t, value)
			}
		default:
			value, err := UnmarshalRefreshEncrypted(signer, "operation", round, blob, enc)
			if err != nil {
				require.Nil(t, value)
			}
		}
	})
}
