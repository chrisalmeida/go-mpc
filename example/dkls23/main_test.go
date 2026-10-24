//go:build darwin || linux

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/chrisalmeida/go-mpc/dkls23"
	"github.com/chrisalmeida/go-mpc/session"
	"github.com/stretchr/testify/require"
	"go-mpc-example/dkls23/node"
	"go-mpc-example/shared"
)

type processRound struct {
	Party, Round int
	Epoch        int
	PublicKey    []byte
	Operation    string
	Kind         session.Kind
	Signing      dkls23.SessionSignInput
	Refresh1     map[int]*dkls23.RefreshRound1Output
	Refresh2     map[int]*dkls23.RefreshRound2Output
}

func TestDKLSColdSigningAndRefreshAcrossProcesses(t *testing.T) {
	if inputPath := os.Getenv("MPC_DKLS_CHILD_INPUT"); inputPath != "" {
		var input processRound
		b, err := os.ReadFile(inputPath)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(b, &input))
		dir := os.Getenv("MPC_DEMO_DIR")
		enc, _, err := shared.LoadOrCreateKey(dir)
		require.NoError(t, err)
		store := &shared.FileStore{Directory: dir}
		scope := session.Scope{Protocol: session.DKLS23, PublicKey: string(input.PublicKey), PartyID: input.Party}
		key, err := session.InspectKey(context.Background(), store, scope)
		require.NoError(t, err)
		codec := dkls23.SessionCodec{Encryptor: enc}
		compute := codec.Signing(input.Signing)
		if input.Kind == session.Refresh {
			compute = codec.Refresh(input.Refresh1, input.Refresh2)
		}
		receipt, err := session.Advance(context.Background(), store, scope, session.Request{Version: key.Version, ID: session.ID{Kind: input.Kind, Epoch: input.Epoch, Value: input.Operation}, Round: input.Round, Participants: allIDs}, compute)
		require.NoError(t, err)
		output := receipt.Output
		if input.Kind == session.Signing || input.Round == 1 {
			output, err = codec.OpenOutput(output, dkls23.KeyBinding{PublicKey: input.PublicKey, PartyID: input.Party, Epoch: input.Epoch}, session.ID{Kind: input.Kind, Epoch: input.Epoch, Value: input.Operation}, input.Round)
			require.NoError(t, err)
		}
		require.NoError(t, os.WriteFile(os.Getenv("MPC_DKLS_CHILD_OUTPUT"), output, 0600))
		return
	}
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	var wrappingKey [32]byte
	_, err := rand.Read(wrappingKey[:])
	require.NoError(t, err)
	shareDir = filepath.Join(dir, "device-store")
	demoStore = &shared.FileStore{Directory: shareDir}
	require.NoError(t, os.Mkdir(shareDir, 0700))
	demoEncryptor = &shared.AESEncryptor{Key: wrappingKey}
	nodes, publicKey := generateAndSave(demoEncryptor)
	env := append(os.Environ(), "MPC_WRAPPING_KEY="+hex.EncodeToString(wrappingKey[:]), "MPC_DEMO_DIR="+shareDir)
	execute := func(input processRound) []byte {
		t.Helper()
		inputPath := filepath.Join(dir, "input.json")
		outputPath := filepath.Join(dir, "output.json")
		b, err := json.Marshal(input)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(inputPath, b, 0600))
		cmd := exec.Command(os.Args[0], "-test.run=^TestDKLSColdSigningAndRefreshAcrossProcesses$")
		cmd.Env = append(env, "MPC_DKLS_CHILD_INPUT="+inputPath, "MPC_DKLS_CHILD_OUTPUT="+outputPath)
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, string(output))
		b, err = os.ReadFile(outputPath)
		require.NoError(t, err)
		return b
	}
	sign := func(epoch int) {
		operation := node.SessionID()
		message := []byte("cold DKLS23 process restart")
		r1 := make(map[int]map[int]*dkls23.Round1Msg)
		r2 := make(map[int]map[int]*dkls23.Round2Msg)
		r3 := make(map[int]map[int]*dkls23.Round3Msg)
		for _, id := range allIDs {
			var out map[int]*dkls23.Round1Msg
			require.NoError(t, json.Unmarshal(execute(processRound{Party: id, Round: 1, Epoch: epoch, PublicKey: publicKey, Operation: operation, Kind: session.Signing}), &out))
			r1[id] = out
		}
		for _, id := range allIDs {
			var out map[int]*dkls23.Round2Msg
			require.NoError(t, json.Unmarshal(execute(processRound{Party: id, Round: 2, Epoch: epoch, PublicKey: publicKey, Operation: operation, Kind: session.Signing, Signing: dkls23.SessionSignInput{Round1: routeMsgs(allIDs, id, r1), Message: message}}), &out))
			r2[id] = out
		}
		for _, id := range allIDs {
			var out map[int]*dkls23.Round3Msg
			require.NoError(t, json.Unmarshal(execute(processRound{Party: id, Round: 3, Epoch: epoch, PublicKey: publicKey, Operation: operation, Kind: session.Signing, Signing: dkls23.SessionSignInput{Round2: routeMsgs(allIDs, id, r2), Message: message}}), &out))
			r3[id] = out
		}
		points := make(map[int][]byte)
		fragments := make(map[int]*dkls23.Round3Msg)
		for _, id := range allIDs {
			for _, m := range r2[id] {
				points[id] = m.Decommitment
				break
			}
			fragments[id] = r3[id][1]
		}
		rx, err := dkls23.ComputeRx(points)
		require.NoError(t, err)
		var w, u btcec.ModNScalar
		w.SetByteSlice(fragments[1].W_i)
		u.SetByteSlice(fragments[1].U_i)
		r, s, err := dkls23.SignCombine(nodes[0].Setup, &rx, &w, &u, fragments, message)
		require.NoError(t, err)
		require.True(t, node.VerifySignature(publicKey, message, r, s))
	}
	sign(0)
	operation := node.SessionID()
	r1 := make(map[int]*dkls23.RefreshRound1Output)
	r2 := make(map[int]*dkls23.RefreshRound2Output)
	for _, id := range allIDs {
		var out dkls23.RefreshRound1Output
		require.NoError(t, json.Unmarshal(execute(processRound{Party: id, Round: 1, PublicKey: publicKey, Operation: operation, Kind: session.Refresh}), &out))
		r1[id] = &out
	}
	for _, id := range allIDs {
		blob := execute(processRound{Party: id, Round: 2, PublicKey: publicKey, Operation: operation, Kind: session.Refresh, Refresh1: r1})
		out, err := (dkls23.SessionCodec{Encryptor: demoEncryptor}).OpenRefreshRound2(blob, dkls23.KeyBinding{PublicKey: publicKey, PartyID: id}, operation)
		require.NoError(t, err)
		r2[id] = out
	}

	for _, id := range allIDs {
		require.Empty(t, execute(processRound{Party: id, Round: 3, PublicKey: publicKey, Operation: operation, Kind: session.Refresh, Refresh1: r1, Refresh2: r2}))
	}
	for _, id := range allIDs {
		scope := session.Scope{Protocol: session.DKLS23, PublicKey: string(publicKey), PartyID: id}
		key, err := session.InspectKey(ctx, demoStore, scope)
		require.NoError(t, err)
		v, err := session.Activate(ctx, demoStore, scope, key.Version, operation)
		require.NoError(t, err)
		require.Equal(t, 1, v.Epoch)
	}
	sign(1)
}
