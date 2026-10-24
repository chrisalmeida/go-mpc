package dkls23

import (
	"bytes"
	"encoding/json"
	"github.com/chrisalmeida/go-mpc/envelope"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestConfidentialRefreshOutputIsBoundEncryptedAndStrict(t *testing.T) {
	t.Parallel()
	signer := fullSetup(t)[1]
	enc := newTestEncryptor()
	_, coeffs, seed, err := RefreshRound1(signer)
	require.NoError(t, err)
	message, err := RefreshRound2(signer, coeffs, seed)
	require.NoError(t, err)
	plaintext, err := json.Marshal(message)
	require.NoError(t, err)
	codec := SessionCodec{enc}
	b := signer.Binding()
	blob, err := sealRefreshOutput(message, b, "refresh", enc)
	require.NoError(t, err)
	context, err := envelope.Peek(blob)
	require.NoError(t, err)
	require.Equal(t, envelope.RefreshOutput, context.Kind)
	restored, err := codec.OpenRefreshRound2(blob, b, "refresh")
	require.NoError(t, err)
	got, err := json.Marshal(restored)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)
	for _, share := range restored.SecretShares {
		require.NotContains(t, string(blob), string(share))
	}
	for _, share := range message.SecretShares {
		require.Equal(t, make([]byte, 32), share, "temporary outbound share erased after sealing")
	}
	_, err = codec.OpenRefreshRound2(blob, b, "other")
	require.Error(t, err)
	altered := bytes.Clone(blob)
	altered[len(altered)-1] ^= 1
	value, err := codec.OpenRefreshRound2(altered, b, "refresh")
	require.Error(t, err)
	require.Nil(t, value)
	_, err = UnmarshalRefreshEncrypted(signer, "refresh", 2, blob, enc)
	require.Error(t, err)
	for name, mutate := range map[string]func(*RefreshRound2Output){"missing shares": func(o *RefreshRound2Output) { o.SecretShares = nil }, "own share": func(o *RefreshRound2Output) { o.SecretShares[b.PartyID] = make([]byte, 32) }, "invalid id": func(o *RefreshRound2Output) { o.SecretShares[0] = make([]byte, 32) }, "short scalar": func(o *RefreshRound2Output) { o.SecretShares[2] = []byte{1} }, "noncanonical scalar": func(o *RefreshRound2Output) { o.SecretShares[2] = bytes.Repeat([]byte{255}, 32) }} {
		t.Run(name, func(t *testing.T) {
			var o RefreshRound2Output
			require.NoError(t, json.Unmarshal(plaintext, &o))
			mutate(&o)
			p, err := json.Marshal(&o)
			require.NoError(t, err)
			if name == "missing shares" {
				var doc map[string]json.RawMessage
				require.NoError(t, json.Unmarshal(p, &doc))
				doc["secret_shares"] = nil
				p, err = json.Marshal(doc)
				require.NoError(t, err)
			}
			forged, err := envelope.Seal(enc, stateContext(b, envelope.RefreshOutput, "refresh", 2), p)
			require.NoError(t, err)
			value, err := codec.OpenRefreshRound2(forged, b, "refresh")
			require.Error(t, err)
			require.Nil(t, value)
		})
	}
}
