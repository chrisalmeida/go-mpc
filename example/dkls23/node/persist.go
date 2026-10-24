package node

import (
	"fmt"
	"os"

	"github.com/chrisalmeida/go-mpc/dkls23"
)

// SaveSetup encrypts and writes the node's SignerSetup to path.
func (n *Node) SaveSetup(path string, enc dkls23.SetupEncryptor) error {
	blob, err := dkls23.MarshalEncrypted(n.Setup, enc)
	if err != nil {
		return fmt.Errorf("node %d SaveSetup: %w", n.ID, err)
	}
	if err := os.WriteFile(path, blob, 0600); err != nil {
		return fmt.Errorf("node %d SaveSetup: write: %w", n.ID, err)
	}
	return nil
}

// LoadSetup reads an encrypted SignerSetup from path and restores it.
func (n *Node) LoadSetup(path string, enc dkls23.SetupEncryptor, expect dkls23.KeyBinding) error {
	blob, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("node %d LoadSetup: read: %w", n.ID, err)
	}
	setup, err := dkls23.UnmarshalEncrypted(blob, enc, expect)
	if err != nil {
		return fmt.Errorf("node %d LoadSetup: %w", n.ID, err)
	}
	n.Setup = setup
	n.ID = setup.MyID
	n.AllIDs = setup.AllIDs
	n.Threshold = setup.Threshold
	return nil
}

// NewFromFile creates a Node by loading an encrypted setup from disk.
func NewFromFile(path string, enc dkls23.SetupEncryptor, expect dkls23.KeyBinding) (*Node, error) {
	n := &Node{}
	if err := n.LoadSetup(path, enc, expect); err != nil {
		return nil, err
	}
	return n, nil
}
