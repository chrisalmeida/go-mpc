package node

import (
	"fmt"
	"os"

	"github.com/chrisalmeida/go-mpc/frost"
)

// SaveKeyShare encrypts only the bare KeyShare, which has no epoch or blacklist.
// Use SaveSignerState to retain that progress. This legacy helper is unchanged.
func (n *Node) SaveKeyShare(path string, enc frost.SetupEncryptor) error {
	ct, err := frost.MarshalEncrypted(n.State.KeyShare, enc)
	if err != nil {
		return fmt.Errorf("node %d SaveKeyShare: %w", n.ID, err)
	}
	if err := os.WriteFile(path, ct, 0600); err != nil {
		return fmt.Errorf("node %d SaveKeyShare: write: %w", n.ID, err)
	}
	return nil
}

// LoadKeyShare reads a bare, epoch-zero KeyShare and creates a new signer state.
// Use LoadSignerState for a refreshed signer or a retained blacklist.
func (n *Node) LoadKeyShare(path string, enc frost.SetupEncryptor, expect frost.KeyBinding) error {
	blob, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("node %d LoadKeyShare: read: %w", n.ID, err)
	}
	ks, err := frost.UnmarshalEncrypted(blob, enc, expect)
	if err != nil {
		return fmt.Errorf("node %d LoadKeyShare: %w", n.ID, err)
	}
	n.State = frost.NewSignerState(ks)
	n.ID = ks.ID
	n.AllIDs = ks.AllIDs
	n.Threshold = ks.Threshold
	return nil
}

// NewFromFile creates a Node by loading an encrypted KeyShare from disk.
func NewFromFile(path string, enc frost.SetupEncryptor, expect frost.KeyBinding) (*Node, error) {
	n := &Node{}
	if err := n.LoadKeyShare(path, enc, expect); err != nil {
		return nil, err
	}
	return n, nil
}

// SaveSignerState encrypts the key share, epoch and blacklist together. It is a
// snapshot helper; authoritative round progress belongs in session.Store, as in
// the main demos. Saving a key snapshot alone does not persist pending nonces.
func (n *Node) SaveSignerState(path string, enc frost.SetupEncryptor) error {
	blob, err := frost.MarshalSignerEncrypted(n.State, enc)
	if err != nil {
		return fmt.Errorf("node %d SaveSignerState: %w", n.ID, err)
	}
	if err := os.WriteFile(path, blob, 0600); err != nil {
		return fmt.Errorf("node %d SaveSignerState: write: %w", n.ID, err)
	}
	return nil
}

// LoadSignerState restores an encrypted signer using a trusted expected binding.
func (n *Node) LoadSignerState(path string, enc frost.SetupEncryptor, expect frost.KeyBinding) error {
	blob, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("node %d LoadSignerState: read: %w", n.ID, err)
	}
	state, err := frost.UnmarshalSignerEncrypted(blob, enc, expect)
	if err != nil {
		return fmt.Errorf("node %d LoadSignerState: %w", n.ID, err)
	}
	n.State = state
	n.ID = state.KeyShare.ID
	n.AllIDs = state.KeyShare.AllIDs
	n.Threshold = state.KeyShare.Threshold
	return nil
}
