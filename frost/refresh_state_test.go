package frost

import (
	"bytes"
	"encoding/json"
	"filippo.io/edwards25519"
	"github.com/stretchr/testify/require"
	"testing"
)

func refreshFixture() *RefreshState {
	return &RefreshState{Round: 1, Coefficients: []*edwards25519.Scalar{scalarFromInt(1)}}
}
func TestRefreshStateUnmarshalErrorsPreserveReceiver(t *testing.T) {
	t.Parallel()
	valid, err := json.Marshal(refreshFixture())
	require.NoError(t, err)
	cases := map[string][]byte{"syntax": []byte("{"), "null": []byte("null"), "trailing": append(append([]byte(nil), valid...), []byte("{}")...), "duplicate": append(append([]byte(nil), valid[:len(valid)-1]...), []byte(`,"round":1}`)...)}
	changes := map[string]any{"version": 2, "round": 3, "coefficients": nil, "seed": "00", "extra": true}
	for field, value := range changes {
		var doc map[string]any
		require.NoError(t, json.Unmarshal(valid, &doc))
		doc[field] = value
		b, err := json.Marshal(doc)
		require.NoError(t, err)
		cases[field] = b
	}
	for _, value := range []string{"00", "gg", string(bytes.Repeat([]byte("ff"), 32))} {
		var doc map[string]any
		require.NoError(t, json.Unmarshal(valid, &doc))
		doc["coefficients"] = []string{value}
		b, err := json.Marshal(doc)
		require.NoError(t, err)
		cases[value] = b
	}
	var doc map[string]any
	require.NoError(t, json.Unmarshal(valid, &doc))
	doc["seed"] = "gg"
	b, err := json.Marshal(doc)
	require.NoError(t, err)
	cases["bad seed hex"] = b
	delete(doc, "version")
	b, err = json.Marshal(doc)
	require.NoError(t, err)
	cases["missing version"] = b
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			state := refreshFixture()
			before, err := json.Marshal(state)
			require.NoError(t, err)
			require.Error(t, json.Unmarshal(input, state))
			after, err := json.Marshal(state)
			require.NoError(t, err)
			require.Equal(t, before, after)
		})
	}
	state := refreshFixture()
	state.Round = 0
	_, err = json.Marshal(state)
	require.Error(t, err)
}
func FuzzUnmarshalRefreshState(f *testing.F) {
	seed, _ := json.Marshal(refreshFixture())
	f.Add(seed)
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		state := refreshFixture()
		before, err := json.Marshal(state)
		require.NoError(t, err)
		err = json.Unmarshal(data, state)
		after, marshalErr := json.Marshal(state)
		require.NoError(t, marshalErr)
		if err != nil {
			require.Equal(t, before, after)
		} else {
			var copy RefreshState
			require.NoError(t, json.Unmarshal(after, &copy))
			again, err := json.Marshal(&copy)
			require.NoError(t, err)
			require.Equal(t, after, again)
		}
	})
}
