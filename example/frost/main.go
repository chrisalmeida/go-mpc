// This example demonstrates a complete 2-of-3 FROST threshold Ed25519 flow:
//
//  1. Key Generation  — Feldman VSS DKG, no trusted dealer (2 rounds)
//  2. Key Refresh     — rotate shares without changing the public key
//  3. Signing         — 2-round threshold Schnorr signing
//  4. Verification    — cofactored Ed25519 + crypto/ed25519 cross-check
//  5. Persistence     — encrypted key shares saved to disk and reloaded
//
// On the first run, DKG executes and shares are saved to shares/.
// On subsequent runs, shares are loaded from disk and DKG is skipped.
//
// Delete the shares/ directory to start fresh.
//
// Each Node is an independent party. The orchestrator here is a stand-in for
// whatever transport you use in production (HTTP, gRPC, message queue, etc.).
//
// Run: cd example/frost && go run .
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"log"
	"path/filepath"

	"go-mpc-example/frost/node"
	"go-mpc-example/shared"

	"github.com/chrisalmeida/go-mpc/frost"
)

const (
	shareDir  = "shares"
	threshold = 2
)

var allIDs = []int{1, 2, 3}

func main() {
	fmt.Println("FROST Threshold Ed25519 — 2-of-3 Demo")
	fmt.Println()

	nodes, pubKey := loadOrGenerate()
	message := []byte("hello threshold Ed25519")

	// ── Signing (before refresh) ────────────────────────────────

	fmt.Println("Phase: Signing (before refresh)")
	signAndPrint(nodes, pubKey, message)

	// ── Key Refresh ─────────────────────────────────────────────

	fmt.Println("Phase: Key Refresh")
	refresh(nodes)
	fmt.Println("  shares rotated, public key unchanged")
	fmt.Println()

	// ── Signing (after refresh) ─────────────────────────────────

	fmt.Println("Phase: Signing (after refresh)")
	signAndPrint(nodes, pubKey, message)

	fmt.Println("Done.")
}

// loadOrGenerate loads existing shares from disk or runs the full DKG.
func loadOrGenerate() (nodes []*node.Node, pubKey []byte) {
	enc, loaded, err := shared.LoadOrCreateKey(shareDir)
	if err != nil {
		log.Fatalf("encryption key: %v", err)
	}
	if loaded {
		return loadShares(enc)
	}
	return generateAndSave(enc)
}

// loadShares reads encrypted share files and returns ready-to-sign nodes.
func loadShares(enc *shared.AESEncryptor) ([]*node.Node, []byte) {
	fmt.Println("Loading key shares from disk...")

	nodes := make([]*node.Node, len(allIDs))
	for i, id := range allIDs {
		p := filepath.Join(shareDir, fmt.Sprintf("node-%d.enc", id))
		n, err := node.NewFromFile(p, enc)
		if err != nil {
			log.Fatalf("load node %d: %v", id, err)
		}
		nodes[i] = n
		fmt.Printf("  node %d loaded\n", n.ID)
	}

	pubKey := nodes[0].PublicKey()
	fmt.Printf("  public key: %s\n\n", hex.EncodeToString(pubKey))
	return nodes, pubKey
}

// generateAndSave runs the 2-round DKG and saves encrypted shares to disk.
func generateAndSave(enc *shared.AESEncryptor) ([]*node.Node, []byte) {
	// ── DKG ─────────────────────────────────────────────────────

	fmt.Println("Phase 1: Key Generation (2-round Feldman VSS DKG)")

	// The DKG context Φ is bound into every party's proof of knowledge of its
	// secret constant term; all parties must agree on it and it should be
	// unique per DKG session so round 1 messages cannot be replayed.
	dkgContext := []byte("go-mpc frost example DKG " + node.SessionID())

	nodes := make([]*node.Node, len(allIDs))
	for i, id := range allIDs {
		nodes[i] = node.New(id, allIDs, threshold, dkgContext)
	}

	// Round 1: broadcast Feldman commitments and proofs of knowledge.
	allRound1 := make(map[int]*frost.DKGRound1Output)
	for _, n := range nodes {
		out, err := n.DKGRound1()
		if err != nil {
			log.Fatalf("DKG round 1 node %d: %v", n.ID, err)
		}
		allRound1[n.ID] = out
		fmt.Printf("  node %d: round 1 complete\n", n.ID)
	}

	// Round 2: verify every other party's proof of knowledge, then decommit shares.
	allRound2 := make(map[int]*frost.DKGRound2Output)
	for _, n := range nodes {
		out, err := n.DKGRound2(allRound1)
		if err != nil {
			log.Fatalf("DKG round 2 node %d: %v", n.ID, err)
		}
		allRound2[n.ID] = out
		fmt.Printf("  node %d: round 2 complete\n", n.ID)
	}

	// Finalize: verify shares, compute key shares.
	for _, n := range nodes {
		if err := n.DKGFinalize(allRound1, allRound2); err != nil {
			log.Fatalf("DKG finalize node %d: %v", n.ID, err)
		}
		fmt.Printf("  node %d: finalized\n", n.ID)
	}

	pubKey := nodes[0].PublicKey()
	fmt.Printf("  public key: %s\n\n", hex.EncodeToString(pubKey))

	// ── Persist ─────────────────────────────────────────────────

	fmt.Println("Phase 2: Saving Key Shares")

	for _, n := range nodes {
		p := filepath.Join(shareDir, fmt.Sprintf("node-%d.enc", n.ID))
		if err := n.SaveKeyShare(p, enc); err != nil {
			log.Fatalf("save node %d: %v", n.ID, err)
		}
		fmt.Printf("  node %d → %s\n", n.ID, p)
	}
	fmt.Println()

	return nodes, pubKey
}

// signAndPrint signs with all 2-of-3 subsets, verifies, and prints verification data.
func signAndPrint(nodes []*node.Node, pubKey []byte, message []byte) {
	fmt.Printf("  message: %q\n", message)

	subsets := [][]int{{1, 2}, {1, 3}, {2, 3}}
	var lastSig *frost.Signature
	for _, signers := range subsets {
		sig := sign(nodes, signers, message)
		lastSig = sig

		fmt.Printf("\n  signers %v:\n", signers)
		fmt.Printf("    R: %s\n", hex.EncodeToString(sig.R))
		fmt.Printf("    z: %s\n", hex.EncodeToString(sig.Z))

		if frost.Verify(pubKey, message, sig) {
			fmt.Println("    frost.Verify: valid")
		} else {
			log.Fatal("    frost.Verify: FAILED")
		}

		if ed25519.Verify(ed25519.PublicKey(pubKey), message, sig.Bytes()) {
			fmt.Println("    ed25519.Verify: valid (RFC 8032 compatible)")
		} else {
			log.Fatal("    ed25519.Verify: FAILED")
		}
	}

	fmt.Println()
	fmt.Println("  Verify at: https://cyphr.me/ed25519_tool/ed.html")
	fmt.Println("  Settings: Algorithm=Ed25519, Msg Encoding=Text(UTF-8), Key Encoding=Hex")
	fmt.Printf("  Public Key: %s\n", hex.EncodeToString(pubKey))
	fmt.Printf("  Signature:  %s\n", hex.EncodeToString(lastSig.Bytes()))
	fmt.Printf("  Message:    %s\n", message)
	fmt.Println()
}

// refresh runs the 2-round key refresh protocol across all nodes.
func refresh(nodes []*node.Node) {
	allRefR1 := make(map[int]*frost.RefreshRound1Output)
	for _, n := range nodes {
		out, err := n.RefreshRound1()
		if err != nil {
			log.Fatalf("refresh round 1 node %d: %v", n.ID, err)
		}
		allRefR1[n.ID] = out
	}

	allRefR2 := make(map[int]*frost.RefreshRound2Output)
	for _, n := range nodes {
		out, err := n.RefreshRound2()
		if err != nil {
			log.Fatalf("refresh round 2 node %d: %v", n.ID, err)
		}
		allRefR2[n.ID] = out
	}

	for _, n := range nodes {
		if err := n.RefreshFinalize(allRefR1, allRefR2); err != nil {
			log.Fatalf("refresh finalize node %d: %v", n.ID, err)
		}
	}
}

// sign runs the 2-round FROST signing protocol across the given nodes.
func sign(nodes []*node.Node, signers []int, message []byte) *frost.Signature {
	nodeMap := make(map[int]*node.Node, len(nodes))
	for _, n := range nodes {
		nodeMap[n.ID] = n
	}

	// Round 1: generate nonce commitments.
	r1States := make(map[int]*frost.Round1State)
	allCommitments := make(map[int]*frost.NonceCommitment)
	for _, id := range signers {
		st, comm, err := nodeMap[id].SignRound1(signers)
		if err != nil {
			log.Fatalf("sign round 1 node %d: %v", id, err)
		}
		r1States[id] = st
		allCommitments[id] = comm
	}

	// Round 2: compute signature shares.
	allShares := make(map[int]*frost.SignatureShare)
	input := &frost.Round2Input{Message: message, AllCommitments: allCommitments}
	for _, id := range signers {
		share, err := nodeMap[id].SignRound2(r1States[id], input)
		if err != nil {
			log.Fatalf("sign round 2 node %d: %v", id, err)
		}
		allShares[id] = share
	}

	// Aggregate: combine shares into final signature.
	verShares := make(map[int][]byte)
	for _, id := range signers {
		verShares[id] = nodeMap[id].KeyShare().VerificationShare
	}

	sig, err := frost.Aggregate(allCommitments, allShares, message, nodeMap[signers[0]].PublicKey(), verShares, signers)
	if err != nil {
		log.Fatalf("aggregate: %v", err)
	}
	return sig
}
