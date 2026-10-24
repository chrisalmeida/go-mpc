package dkls23

import (
	"encoding/json"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/chrisalmeida/go-mpc/envelope"
	"github.com/stretchr/testify/require"
	"testing"
)

func FuzzUnmarshalEncryptedPrivateState(f *testing.F) {
	var scalar btcec.ModNScalar
	scalar.SetInt(1)
	pk, err := scalarMulGCompressed(&scalar)
	if err != nil {
		f.Fatal(err)
	}
	signer := &SignerSetup{MyID: 1, AllIDs: []int{1}, Threshold: 1, PubKey: pk, Share: scalar}
	enc := newTestEncryptor()
	binding := signer.Binding()
	// Every dispatch branch gets a valid seed, including outbound round 2.
	keyBlob, err := MarshalEncrypted(signer, enc)
	if err != nil {
		f.Fatal(err)
	}
	keyPayload, err := envelope.Open(enc, stateContext(binding, envelope.Setup, "", 0), keyBlob)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(uint8(0), keyPayload)
	state1, _, err := SignRound1(signer, "operation", []int{1})
	if err != nil {
		f.Fatal(err)
	}
	blob1, err := MarshalRound1Encrypted(signer, state1, enc)
	if err != nil {
		f.Fatal(err)
	}
	payload1, err := envelope.Open(enc, stateContext(binding, envelope.Sign1, "operation", 1), blob1)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(uint8(1), payload1)
	state2, _, err := SignRound2(signer, state1, nil)
	if err != nil {
		f.Fatal(err)
	}
	blob2, err := MarshalRound2Encrypted(signer, state2, enc)
	if err != nil {
		f.Fatal(err)
	}
	payload2, err := envelope.Open(enc, stateContext(binding, envelope.Sign2, "operation", 2), blob2)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(uint8(2), payload2)
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
	f.Add(uint8(5), []byte("0")) // Regression: output dispatch must select round 2.
	f.Fuzz(func(t *testing.T, choice uint8, payload []byte) {
		choice %= 6
		kinds := []string{envelope.Setup, envelope.Sign1, envelope.Sign2, envelope.Refresh1, envelope.Refresh2, envelope.RefreshOutput}
		round := 0
		if choice == 1 || choice == 3 {
			round = 1
		}
		if choice == 2 || choice == 4 || choice == 5 {
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
			value, err := UnmarshalRound1Encrypted(signer, "operation", blob, enc)
			if err != nil {
				require.Nil(t, value)
			}
		case 2:
			value, err := UnmarshalRound2Encrypted(signer, "operation", blob, enc)
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
