//go:build darwin || linux

package shared

import (
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/chrisalmeida/go-mpc/session"
	"github.com/chrisalmeida/go-mpc/session/storetest"
	"github.com/stretchr/testify/require"
)

func TestFileStoreConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) (session.Store, func() session.Store) {
		dir := t.TempDir()
		return &FileStore{Directory: dir}, func() session.Store { return &FileStore{Directory: dir} }
	})
}

func fileTestScope() session.Scope {
	return session.Scope{Protocol: session.FROST, PublicKey: strings.Repeat("p", 32), PartyID: 1}
}

func TestFileStoreReopensAfterUnrelatedGobEncoding(t *testing.T) {
	if mode := os.Getenv("MPC_STORE_GOB_MODE"); mode != "" {
		if mode == "write" {
			// Gob assigns user type IDs in process-global encounter order.
			var unrelated bytes.Buffer
			require.NoError(t, gob.NewEncoder(&unrelated).Encode(struct{ Unrelated string }{"metadata"}))
		}
		store := &FileStore{Directory: os.Getenv("MPC_STORE_DIRECTORY")}
		ctx := context.Background()
		id := session.ID{Kind: session.Signing, Epoch: 0, Value: "pending-operation"}
		if mode == "write" {
			_, err := session.Initialize(ctx, store, fileTestScope(), 0, []byte("encrypted key"))
			require.NoError(t, err)
			require.NoError(t, store.Transact(ctx, fileTestScope(), func(tx session.Transaction) error {
				if err := tx.PutSession(id, session.Record{Round: 1, Checkpoint: []byte("encrypted private state"), Participants: []int{1, 2}, Outputs: map[int][]byte{1: []byte("encrypted committed output")}}); err != nil {
					return err
				}
				return tx.UseNonce("\xff\x00reserved nonce")
			}))
		} else {
			key, err := session.InspectKey(ctx, store, fileTestScope())
			require.NoError(t, err)
			require.Equal(t, []byte("encrypted key"), key.Checkpoint)
			require.NoError(t, store.Transact(ctx, fileTestScope(), func(tx session.Transaction) error {
				record, ok, err := tx.Session(id)
				require.NoError(t, err)
				require.True(t, ok)
				require.Equal(t, 1, record.Round)
				require.Equal(t, []byte("encrypted private state"), record.Checkpoint)
				require.Equal(t, []byte("encrypted committed output"), record.Outputs[1])
				used, err := tx.NonceUsed("\xff\x00reserved nonce")
				require.True(t, used)
				return err
			}))
		}
		return
	}
	t.Parallel()
	dir := t.TempDir()
	var original []byte
	var originalPath string
	for _, mode := range []string{"write", "read"} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestFileStoreReopensAfterUnrelatedGobEncoding$")
		cmd.Env = append(os.Environ(), "MPC_STORE_GOB_MODE="+mode, "MPC_STORE_DIRECTORY="+dir)
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, string(output))
		files, err := filepath.Glob(filepath.Join(dir, "*.state"))
		require.NoError(t, err)
		require.Len(t, files, 1)
		retained, err := os.ReadFile(files[0])
		require.NoError(t, err)
		if mode == "write" {
			originalPath, original = files[0], retained
		} else {
			require.Equal(t, originalPath, files[0])
			require.Equal(t, original, retained)
		}
	}
}

func TestFileStoreCrashAndConcurrentProcesses(t *testing.T) {
	if os.Getenv("MPC_STORE_CHILD") == "1" {
		if os.Getenv("MPC_STORE_GOB_PRIME") == "1" {
			var unrelated bytes.Buffer
			require.NoError(t, gob.NewEncoder(&unrelated).Encode(struct{ Unrelated int }{42}))
		}
		store := &FileStore{Directory: os.Getenv("MPC_STORE_DIRECTORY")}
		if stage := os.Getenv("MPC_STORE_KILL_STAGE"); stage != "" {
			store.commitHook = func(at string) {
				if at == stage {
					require.NoError(t, os.WriteFile(filepath.Join(store.Directory, "ready"), []byte(at), 0600))
					select {}
				}
			}
		}
		err := store.Transact(context.Background(), fileTestScope(), func(tx session.Transaction) error {
			key, _, err := tx.Key()
			if err != nil {
				return err
			}
			key.Revision++
			key.Checkpoint = []byte("encrypted checkpoint")
			return tx.PutKey(key)
		})
		require.NoError(t, err)
		return
	}
	t.Parallel()
	for _, stage := range []string{"before-rename", "after-rename"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			store := &FileStore{Directory: dir}
			_, err := session.Initialize(context.Background(), store, fileTestScope(), 0, []byte("previous encrypted key"))
			require.NoError(t, err)
			cmd := exec.Command(os.Args[0], "-test.run=^TestFileStoreCrashAndConcurrentProcesses$")
			cmd.Env = append(os.Environ(), "MPC_STORE_CHILD=1", "MPC_STORE_DIRECTORY="+dir, "MPC_STORE_KILL_STAGE="+stage)
			require.NoError(t, cmd.Start())
			t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
			deadline := time.Now().Add(10 * time.Second)
			for {
				if _, err := os.Stat(filepath.Join(dir, "ready")); err == nil {
					break
				}
				require.True(t, time.Now().Before(deadline), "child did not reach commit boundary")
				time.Sleep(10 * time.Millisecond)
			}
			require.NoError(t, cmd.Process.Kill())
			require.Error(t, cmd.Wait())
			key, err := session.InspectKey(context.Background(), &FileStore{Directory: dir}, fileTestScope())
			require.NoError(t, err)
			expected := uint64(1)
			if stage == "after-rename" {
				expected = 2
			}
			require.Equal(t, expected, key.Revision)
			if stage == "before-rename" {
				require.Equal(t, "previous encrypted key", string(key.Checkpoint))
			} else {
				require.Equal(t, "encrypted checkpoint", string(key.Checkpoint))
			}
		})
	}
	dir := t.TempDir()
	store := &FileStore{Directory: dir}
	_, err := session.Initialize(context.Background(), store, fileTestScope(), 0, []byte("key"))
	require.NoError(t, err)
	const count = 8
	cmds := make([]*exec.Cmd, count)
	for i := range cmds {
		cmd := exec.Command(os.Args[0], "-test.run=^TestFileStoreCrashAndConcurrentProcesses$")
		cmd.Env = append(os.Environ(), "MPC_STORE_CHILD=1", "MPC_STORE_DIRECTORY="+dir, "MPC_STORE_KILL_STAGE=", "MPC_STORE_GOB_PRIME="+strconv.Itoa(i%2))
		cmds[i] = cmd
		require.NoError(t, cmd.Start())
	}
	for i, cmd := range cmds {
		require.NoError(t, cmd.Wait(), fmt.Sprint(i))
	}
	key, err := session.InspectKey(context.Background(), store, fileTestScope())
	require.NoError(t, err)
	require.Equal(t, uint64(count+1), key.Revision)
}

func TestFileStoreRejectsDuplicateScopeFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	store := &FileStore{Directory: dir}
	_, err := session.Initialize(context.Background(), store, fileTestScope(), 0, []byte("encrypted key"))
	require.NoError(t, err)
	files, err := filepath.Glob(filepath.Join(dir, "*.state"))
	require.NoError(t, err)
	require.Len(t, files, 1)
	original, err := os.ReadFile(files[0])
	require.NoError(t, err)
	duplicate := filepath.Join(dir, "duplicate.state")
	require.NoError(t, os.WriteFile(duplicate, original, 0600))
	called := false
	err = store.Transact(context.Background(), fileTestScope(), func(session.Transaction) error { called = true; return nil })
	require.ErrorContains(t, err, "duplicate files for scope")
	require.False(t, called)
	for _, path := range []string{files[0], duplicate} {
		retained, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, original, retained)
	}
}

func TestFileStorePreservesBinaryIdentifiersAndRejectsCorruption(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	scope := fileTestScope()
	scope.PublicKey = string(append([]byte{0xff, 0x00}, make([]byte, 30)...))
	id := session.ID{Kind: session.Signing, Value: "\xff\x00", Epoch: 0}
	store := &FileStore{Directory: dir}
	require.NoError(t, store.Transact(context.Background(), scope, func(tx session.Transaction) error {
		return tx.PutSession(id, session.Record{Round: 1, Outputs: map[int][]byte{1: {0xff}}})
	}))
	require.NoError(t, (&FileStore{Directory: dir}).Transact(context.Background(), scope, func(tx session.Transaction) error {
		r, ok, err := tx.Session(id)
		require.True(t, ok)
		require.Equal(t, []byte{0xff}, r.Outputs[1])
		return err
	}))
	files, err := filepath.Glob(filepath.Join(dir, "*.state"))
	require.NoError(t, err)
	require.Len(t, files, 1)
	require.NoError(t, os.WriteFile(files[0], []byte(strconv.Itoa(42)), 0600))
	called := false
	require.Error(t, store.Transact(context.Background(), scope, func(session.Transaction) error { called = true; return nil }))
	require.False(t, called)
}

func TestFileStoreDoesNotInheritMetadataWhenDecoding(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	store := &FileStore{Directory: dir}
	scope := fileTestScope()
	_, err := session.Initialize(ctx, store, scope, 0, []byte("encrypted key"))
	require.NoError(t, err)
	files, err := filepath.Glob(filepath.Join(dir, "*.state"))
	require.NoError(t, err)
	require.Len(t, files, 1)
	for _, change := range []func(*filePartition){func(p *filePartition) { p.Version = 0 }, func(p *filePartition) { p.Scope = session.Scope{} }, func(p *filePartition) { p.Version = 2 }, func(p *filePartition) { p.Scope.PartyID++ }} {
		p := filePartition{Version: 1, Scope: scope, HasKey: true, KeyRecord: session.KeyRecord{Version: session.Version{Revision: 1}, Checkpoint: []byte("encrypted key")}, Sessions: map[session.ID]session.Record{{Kind: session.Signing, Value: "op"}: {Round: 1}}, Nonces: map[string]bool{"marker": true}}
		change(&p)
		var encoded bytes.Buffer
		require.NoError(t, gob.NewEncoder(&encoded).Encode(p))
		require.NoError(t, os.WriteFile(files[0], encoded.Bytes(), 0600))
		called := false
		err = store.Transact(ctx, scope, func(session.Transaction) error { called = true; return nil })
		require.Error(t, err)
		require.False(t, called)
		retained, err := os.ReadFile(files[0])
		require.NoError(t, err)
		require.Equal(t, encoded.Bytes(), retained)
	}
}
