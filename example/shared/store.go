package shared

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/chrisalmeida/go-mpc/session"
)

// FileStore is an example session.Store for local Linux/macOS filesystems. Each
// scope commits as one file, using a kernel lock, temporary write, fsync, rename,
// and directory fsync. It assumes a trusted private directory on a local filesystem
// honoring those operations. It does not defend against snapshot rollback, hostile
// local file replacement, or promise physical erasure or hardware power-loss safety.
// Private checkpoints must already be encrypted by the library codecs.
type FileStore struct {
	Directory  string
	commitHook func(string) // subprocess crash tests only; never retries a callback
}

type filePartition struct {
	Version   int
	Scope     session.Scope
	KeyRecord session.KeyRecord
	HasKey    bool
	Sessions  map[session.ID]session.Record
	Nonces    map[string]bool
}

// Transact serializes a whole scope across connections and processes. It invokes
// fn once and publishes writes only on nil callback error and uncancelled context.
// An error after rename has an uncertain outcome; recover with session.Output.
func (s *FileStore) Transact(ctx context.Context, scope session.Scope, fn func(session.Transaction) error) error {
	if s == nil || s.Directory == "" || ctx == nil || fn == nil {
		return fmt.Errorf("file store: invalid arguments")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(s.Directory, 0700); err != nil {
		return err
	}
	// Lock an unambiguous encoding, not Gob's process-local user type IDs.
	// Keep the existing data filenames: discovery below uses the stored Scope,
	// so upgrading does not discard keys, pending checkpoints or nonce history.
	var lockBytes []byte
	for _, value := range []string{string(scope.Protocol), scope.PublicKey} {
		lockBytes = binary.BigEndian.AppendUint64(lockBytes, uint64(len(value)))
		lockBytes = append(lockBytes, value...)
	}
	lockBytes = binary.BigEndian.AppendUint64(lockBytes, uint64(scope.PartyID))
	lockDigest := sha256.Sum256(lockBytes)
	unlockScope, err := lockScope(ctx, filepath.Join(s.Directory, "scope-"+hex.EncodeToString(lockDigest[:])+".lock"))
	if err != nil {
		return err
	}
	defer unlockScope()
	var scopeBytes bytes.Buffer
	if err := gob.NewEncoder(&scopeBytes).Encode(scope); err != nil {
		return err
	}
	digest := sha256.Sum256(scopeBytes.Bytes())
	base := filepath.Join(s.Directory, hex.EncodeToString(digest[:]))
	base, err = findPartition(s.Directory, base, scope)
	if err != nil {
		return err
	}
	// Also retain the original file lock for an existing partition.
	unlock, err := lockScope(ctx, base+".lock")
	if err != nil {
		return err
	}
	defer unlock()
	partition := filePartition{Version: 1, Scope: scope, Sessions: make(map[session.ID]session.Record), Nonces: make(map[string]bool)}
	decoded, err := readPartition(base + ".state")
	if err == nil {
		if decoded.Scope != scope {
			return fmt.Errorf("file store: corrupt or incompatible state")
		}
		partition = decoded
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tx := &fileTransaction{data: partition}
	if err := fn(tx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !tx.dirty {
		return nil
	}
	tmp, err := os.CreateTemp(s.Directory, ".commit-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	// CreateTemp uses 0600; the temporary contains ciphertext and progress only.
	if err := gob.NewEncoder(tmp).Encode(tx.data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if s.commitHook != nil {
		s.commitHook("before-rename")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), base+".state"); err != nil {
		return err
	}
	if s.commitHook != nil {
		s.commitHook("after-rename")
	}
	directory, err := os.Open(s.Directory)
	if err != nil {
		return err
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil {
		return err
	}
	return closeErr
}

// findPartition retains an existing filename even when another process assigned
// different Gob type IDs. More than one file for a scope is ambiguous and fails
// closed. Temporary commit files and lock files are not partitions.
func findPartition(directory, initial string, scope session.Scope) (string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return "", err
	}
	var found string
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".state") {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		partition, err := readPartition(path)
		if err != nil {
			return "", err
		}
		if partition.Scope != scope {
			if path == initial+".state" {
				return "", fmt.Errorf("file store: corrupt scope metadata")
			}
			continue
		}
		if found != "" {
			return "", fmt.Errorf("file store: duplicate files for scope")
		}
		found = strings.TrimSuffix(path, ".state")
	}
	if found != "" {
		return found, nil
	}
	return initial, nil
}

func readPartition(path string) (filePartition, error) {
	file, err := os.Open(path)
	if err != nil {
		return filePartition{}, err
	}
	decoder := gob.NewDecoder(file)
	// Gob merges into its receiver. Omitted fields must stay zero values.
	var decoded filePartition
	err = decoder.Decode(&decoded)
	if err == nil {
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			err = fmt.Errorf("file store: trailing state")
		}
	}
	closeErr := file.Close()
	if err != nil {
		return filePartition{}, fmt.Errorf("file store: decode: %w", err)
	}
	if closeErr != nil {
		return filePartition{}, closeErr
	}
	if decoded.Version != 1 || decoded.Scope == (session.Scope{}) || decoded.Sessions == nil || decoded.Nonces == nil {
		return filePartition{}, fmt.Errorf("file store: corrupt or incompatible state")
	}
	return decoded, nil
}

type fileTransaction struct {
	data  filePartition
	dirty bool
}

func copyValue[T any](value T) T {
	// All transaction values are concrete exported session structs, bytes and ints.
	// In-memory encoding gives every nested map and byte slice independent ownership.
	var b bytes.Buffer
	if err := gob.NewEncoder(&b).Encode(value); err != nil {
		panic(err)
	}
	var clone T
	if err := gob.NewDecoder(&b).Decode(&clone); err != nil {
		panic(err)
	}
	return clone
}
func (t *fileTransaction) Key() (session.KeyRecord, bool, error) {
	return copyValue(t.data.KeyRecord), t.data.HasKey, nil
}
func (t *fileTransaction) PutKey(key session.KeyRecord) error {
	t.data.KeyRecord = copyValue(key)
	t.data.HasKey = true
	t.dirty = true
	return nil
}
func (t *fileTransaction) Session(id session.ID) (session.Record, bool, error) {
	r, ok := t.data.Sessions[id]
	return copyValue(r), ok, nil
}
func (t *fileTransaction) PutSession(id session.ID, r session.Record) error {
	t.data.Sessions[id] = copyValue(r)
	t.dirty = true
	return nil
}
func (t *fileTransaction) NonceUsed(id string) (bool, error) { return t.data.Nonces[id], nil }
func (t *fileTransaction) UseNonce(id string) error {
	t.data.Nonces[id] = true
	t.dirty = true
	return nil
}
