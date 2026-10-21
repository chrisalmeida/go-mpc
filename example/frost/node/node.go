// Package node wraps the frost package into a self-contained Node that
// models a single party in a threshold Ed25519 deployment.
package node

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"filippo.io/edwards25519"
	"github.com/chrisalmeida/go-mpc/frost"
)

// Node is a single FROST party.
type Node struct {
	ID        int
	AllIDs    []int
	Threshold int
	State     *frost.SignerState

	dkgConfig     frost.DKGPartyConfig
	dkgCoeffs     []*edwards25519.Scalar
	refreshCoeffs []*edwards25519.Scalar
	refreshSeed   [16]byte
}

// New creates a Node for the given party ID.
//
// dkgContext is the DKG context string Φ bound into this party's proof of
// knowledge of its secret polynomial constant term (FROST paper, Figure 1).
// Every party in the same DKG session must use the same value, and it should
// be unique per session (for example an application name plus SessionID()) so
// that round 1 messages from one DKG cannot be replayed into another.
func New(id int, allIDs []int, threshold int, dkgContext []byte) *Node {
	return &Node{
		ID:        id,
		AllIDs:    allIDs,
		Threshold: threshold,
		dkgConfig: frost.DKGPartyConfig{MyID: id, AllIDs: allIDs, Threshold: threshold, Context: dkgContext},
	}
}

// SessionID returns a fresh random session identifier.
func SessionID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// ── Key Generation ──────────────────────────────────────────────

func (n *Node) DKGRound1() (*frost.DKGRound1Output, error) {
	out, coeffs, err := frost.DKGRound1(n.dkgConfig)
	if err != nil {
		return nil, fmt.Errorf("node %d DKGRound1: %w", n.ID, err)
	}
	n.dkgCoeffs = coeffs
	return out, nil
}

// DKGRound2 verifies every other party's round 1 proof of knowledge and, only
// if all verify, returns the shares to send to each other party. A failure
// names the offending parties and releases nothing.
func (n *Node) DKGRound2(allRound1 map[int]*frost.DKGRound1Output) (*frost.DKGRound2Output, error) {
	out, err := frost.DKGRound2(n.dkgConfig, n.dkgCoeffs, allRound1)
	if err != nil {
		return nil, fmt.Errorf("node %d DKGRound2: %w", n.ID, err)
	}
	return out, nil
}

func (n *Node) DKGFinalize(
	allRound1 map[int]*frost.DKGRound1Output,
	allRound2 map[int]*frost.DKGRound2Output,
) error {
	ks, err := frost.DKGFinalize(n.dkgConfig, n.dkgCoeffs, allRound1, allRound2)
	if err != nil {
		return fmt.Errorf("node %d DKGFinalize: %w", n.ID, err)
	}
	n.State = frost.NewSignerState(ks)
	n.dkgCoeffs = nil
	return nil
}

// PublicKey returns the group public key (32-byte compressed Edwards point).
func (n *Node) PublicKey() []byte {
	if n.State == nil {
		return nil
	}
	return n.State.KeyShare.PublicKey
}

// KeyShare returns the underlying KeyShare (for persistence / verification shares).
func (n *Node) KeyShare() *frost.KeyShare {
	if n.State == nil {
		return nil
	}
	return n.State.KeyShare
}

// ── Signing ─────────────────────────────────────────────────────

func (n *Node) SignRound1(signers []int) (*frost.Round1State, *frost.NonceCommitment, error) {
	return frost.SignRound1(n.State, signers)
}

func (n *Node) SignRound2(state *frost.Round1State, input *frost.Round2Input) (*frost.SignatureShare, error) {
	return frost.SignRound2(n.State, state, input)
}

// ── Key Refresh ─────────────────────────────────────────────────

func (n *Node) RefreshRound1() (*frost.RefreshRound1Output, error) {
	out, coeffs, seed, err := frost.RefreshRound1(n.State)
	if err != nil {
		return nil, fmt.Errorf("node %d RefreshRound1: %w", n.ID, err)
	}
	n.refreshCoeffs = coeffs
	n.refreshSeed = seed
	return out, nil
}

func (n *Node) RefreshRound2() (*frost.RefreshRound2Output, error) {
	out, err := frost.RefreshRound2(n.State, n.refreshCoeffs, n.refreshSeed)
	if err != nil {
		return nil, fmt.Errorf("node %d RefreshRound2: %w", n.ID, err)
	}
	return out, nil
}

func (n *Node) RefreshFinalize(
	allRound1 map[int]*frost.RefreshRound1Output,
	allRound2 map[int]*frost.RefreshRound2Output,
) error {
	err := frost.RefreshFinalize(n.State, n.refreshCoeffs, n.refreshSeed, allRound1, allRound2)
	n.refreshCoeffs = nil
	n.refreshSeed = [16]byte{}
	if err != nil {
		return fmt.Errorf("node %d RefreshFinalize: %w", n.ID, err)
	}
	return nil
}

// Epoch returns the current refresh epoch (0 before any refresh).
func (n *Node) Epoch() int {
	if n.State == nil {
		return 0
	}
	return n.State.Epoch
}
