//go:build darwin || linux

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/chrisalmeida/go-mpc/session"
	"github.com/stretchr/testify/require"
	"go-mpc-example/shared"
)

func TestColdDKLSCommandsRestartRelocateAndRecoverOutput(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	binary := filepath.Join(dir, "cold-dkls23")
	build := exec.Command("go", "build", "-race", "-o", binary, ".")
	output, err := build.CombinedOutput()
	require.NoError(t, err, string(output))
	var key [32]byte
	_, err = rand.Read(key[:])
	require.NoError(t, err)
	env := append(os.Environ(), "MPC_WRAPPING_KEY="+hex.EncodeToString(key[:]))
	command := func(args ...string) {
		t.Helper()
		cmd := exec.Command(binary, args...)
		cmd.Env = env
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, string(output))
	}
	root := filepath.Join(dir, "coordinator")
	command("init", root)
	var cfg configuration
	require.NoError(t, read(filepath.Join(root, "group.json"), &cfg))
	message := []byte("manual cold DKLS signing commands")
	messagePath := filepath.Join(root, "message.txt")
	require.NoError(t, os.WriteFile(messagePath, message, 0600))
	device1 := filepath.Join(root, "device-1")
	const operation = "cold-example-operation"
	for round := 1; round <= 3; round++ {
		command("request", root, operation, strconv.Itoa(round), messagePath)
		for _, id := range cfg.Participants {
			var input roundRequest
			require.NoError(t, read(requestPath(root, round, id), &input))
			if round == 2 {
				require.Len(t, input.Input.Round1, len(cfg.Participants)-1)
				require.NotContains(t, input.Input.Round1, id)
				require.Empty(t, input.Input.Round2)
			}
			if round == 3 {
				require.Len(t, input.Input.Round2, len(cfg.Participants)-1)
				require.NotContains(t, input.Input.Round2, id)
				require.Empty(t, input.Input.Round1)
			}
			device := filepath.Join(root, "device-"+strconv.Itoa(id))
			if id == 1 {
				device = device1
			}
			if round == 1 && id == 1 {
				// The round commits before file delivery; retry must recover it
				// even though the first process exited with a write error.
				cmd := exec.Command(binary, "round", device, requestPath(root, round, id), filepath.Join(root, "missing-directory", "reply.json"))
				cmd.Env = env
				output, err := cmd.CombinedOutput()
				require.Error(t, err, string(output))
			}
			command("round", device, requestPath(root, round, id), roundPath(root, round, id))
		}
		if round == 1 {
			// Move the complete device store between commands, including its
			// authoritative progress. No old copy is used after relocation.
			device1 = filepath.Join(dir, "relocated-offline-device")
			require.NoError(t, os.Rename(filepath.Join(root, "device-1"), device1))
		}
	}
	resultPath := filepath.Join(root, "signature.der")
	for _, id := range []int{2, 3} {
		require.NoError(t, os.Rename(filepath.Join(root, "device-"+strconv.Itoa(id)), filepath.Join(dir, "offline-"+strconv.Itoa(id))))
	}
	// Only protocol files and public group configuration remain at the
	// coordinator. Combining must work without a wrapping key or device store.
	combineCommand := exec.Command(binary, "combine", root, operation, messagePath, resultPath)
	combineCommand.Env = append(os.Environ(), "MPC_WRAPPING_KEY=")
	output, err = combineCommand.CombinedOutput()
	require.NoError(t, err, string(output))
	der, err := os.ReadFile(resultPath)
	require.NoError(t, err)
	sig, err := ecdsa.ParseDERSignature(der)
	require.NoError(t, err)
	pk, err := btcec.ParsePubKey(cfg.PublicKey)
	require.NoError(t, err)
	hash := sha256.Sum256(message)
	require.True(t, sig.Verify(hash[:], pk))
	wrongHash := sha256.Sum256([]byte("another message"))
	require.False(t, sig.Verify(wrongHash[:], pk))

	// A changed message cannot create a second round-3 result for the same
	// operation. The CLI returns the original output without a new revision.
	store := &shared.FileStore{Directory: device1}
	scope := session.Scope{Protocol: session.DKLS23, PublicKey: string(cfg.PublicKey), PartyID: 1}
	before, err := session.InspectKey(context.Background(), store, scope)
	require.NoError(t, err)
	original, err := os.ReadFile(roundPath(root, 3, 1))
	require.NoError(t, err)
	var req roundRequest
	require.NoError(t, read(requestPath(root, 3, 1), &req))
	req.Input.Message = []byte("attempted second message")
	require.NoError(t, write(requestPath(root, 3, 1), req))
	recoveredPath := filepath.Join(root, "recovered.json")
	command("round", device1, requestPath(root, 3, 1), recoveredPath)
	recovered, err := os.ReadFile(recoveredPath)
	require.NoError(t, err)
	require.Equal(t, original, recovered)
	after, err := session.InspectKey(context.Background(), store, scope)
	require.NoError(t, err)
	require.Equal(t, before.Version, after.Version)

	// Coordinator routing metadata must reject accidentally mixed operations.
	cmd := exec.Command(binary, "request", root, "different-operation", "2", messagePath)
	cmd.Env = env
	output, err = cmd.CombinedOutput()
	require.Error(t, err, string(output))
	require.Contains(t, string(output), "mismatched output routing metadata")

	// A fresh round with the wrong wrapping key produces no transport output.
	command("request", root, "fresh-operation", "1", messagePath)
	unexpected := filepath.Join(root, "unexpected.json")
	cmd = exec.Command(binary, "round", device1, requestPath(root, 1, 1), unexpected)
	cmd.Env = append(os.Environ(), "MPC_WRAPPING_KEY="+hex.EncodeToString(make([]byte, 32)))
	output, err = cmd.CombinedOutput()
	require.Error(t, err, string(output))
	require.NoFileExists(t, unexpected)

	// Combining fragments for a different message fails before writing a signature.
	require.NoError(t, os.WriteFile(messagePath, []byte("wrong message"), 0600))
	cmd = exec.Command(binary, "combine", root, operation, messagePath, unexpected)
	cmd.Env = env
	output, err = cmd.CombinedOutput()
	require.Error(t, err, string(output))
	require.NoFileExists(t, unexpected)
}
