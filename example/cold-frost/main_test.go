//go:build darwin || linux

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestColdSigningSeparateProcessesAndCachedOutput(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	binary := filepath.Join(dir, "cold-frost")
	build := exec.Command("go", "build", "-race", "-o", binary, ".")
	output, err := build.CombinedOutput()
	require.NoError(t, err, string(output))
	var key [32]byte
	_, err = rand.Read(key[:])
	require.NoError(t, err)
	env := append(os.Environ(), "MPC_WRAPPING_KEY="+hex.EncodeToString(key[:]))
	root := filepath.Join(dir, "devices")
	command := func(args ...string) {
		t.Helper()
		cmd := exec.Command(binary, args...)
		cmd.Env = env
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, string(output))
	}
	command("init", root)
	const operation = "manual-cold-frost"
	device1 := filepath.Join(root, "device-1")
	device2 := filepath.Join(root, "device-2")
	firstCommitment := filepath.Join(root, "commitment-1.json")
	secondCommitment := filepath.Join(root, "commitment-2.json")
	command("commit", device1, operation, firstCommitment)
	command("commit", device2, operation, secondCommitment)
	// The complete authoritative device state is portable between commands.
	relocated := filepath.Join(dir, "relocated-device")
	require.NoError(t, os.Rename(device1, relocated))
	device1 = relocated
	messagePath := filepath.Join(root, "message.txt")
	require.NoError(t, os.WriteFile(messagePath, []byte("manual offline file transfer"), 0600))
	requestPath := filepath.Join(root, "request.json")
	command("request", root, operation, messagePath, firstCommitment, secondCommitment, requestPath)
	firstShare := filepath.Join(root, "share-1.json")
	secondShare := filepath.Join(root, "share-2.json")
	// Commit succeeds even if delivery of its output file fails. Retrying
	// below must recover that committed round rather than consume new nonces.
	failedDelivery := exec.Command(binary, "sign", device1, operation, requestPath, filepath.Join(root, "missing-directory", "share.json"))
	failedDelivery.Env = env
	output, err = failedDelivery.CombinedOutput()
	require.Error(t, err, string(output))
	command("sign", device1, operation, requestPath, firstShare)
	command("sign", device2, operation, requestPath, secondShare)
	aggregate := exec.Command(binary, "aggregate", root, requestPath, firstShare, secondShare, filepath.Join(root, "signature.bin"))
	aggregate.Env = append(os.Environ(), "MPC_WRAPPING_KEY=")
	output, err = aggregate.CombinedOutput()
	require.NoError(t, err, string(output))
	var group configuration
	require.NoError(t, read(filepath.Join(root, "group.json"), &group))
	var req signingRequest
	require.NoError(t, read(requestPath, &req))
	signature, err := os.ReadFile(filepath.Join(root, "signature.bin"))
	require.NoError(t, err)
	require.True(t, ed25519.Verify(group.PublicKey, req.Message, signature))
	original, err := os.ReadFile(filepath.Join(root, "share-1.json"))
	require.NoError(t, err)
	req.Message = []byte("attempt to sign a second message with the same nonces")
	require.NoError(t, write(requestPath, req))
	again := filepath.Join(root, "recovered-share.json")
	command("sign", device1, req.OperationID, requestPath, again)
	recovered, err := os.ReadFile(again)
	require.NoError(t, err)
	require.Equal(t, original, recovered)
	recoveredCommitment := filepath.Join(root, "recovered-commitment.json")
	command("commit", device1, req.OperationID, recoveredCommitment)
	originalCommitment, err := os.ReadFile(firstCommitment)
	require.NoError(t, err)
	commitment, err := os.ReadFile(recoveredCommitment)
	require.NoError(t, err)
	require.Equal(t, originalCommitment, commitment)
	// Wrong wrapping key fails without creating a public share file.
	cmd := exec.Command(binary, "commit", filepath.Join(root, "device-2"), "fresh-operation", filepath.Join(root, "unexpected"))
	cmd.Env = append(os.Environ(), "MPC_WRAPPING_KEY="+hex.EncodeToString(make([]byte, 32)))
	output, err = cmd.CombinedOutput()
	require.Error(t, err, string(output))
	_, err = os.Stat(filepath.Join(root, "unexpected"))
	require.True(t, os.IsNotExist(err))
}
