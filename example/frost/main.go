// This example demonstrates a complete 2-of-3 FROST threshold Ed25519 flow:
//
//  1. Key Generation  — Feldman VSS DKG, no trusted dealer (2 rounds)
//  2. Persistence     — encrypted signer state and authoritative session progress
//  3. Signing         — all 2-of-3 subsets, checked with crypto/ed25519
//  4. Key Refresh     — prepare every party, activate, reload, and sign again
//
// Set MPC_WRAPPING_KEY to a 32-byte hex demo key and retain it between runs.
// MPC_DEMO_DIR selects the store directory (default shares/). The first run
// creates a group; subsequent runs reload it and skip DKG. Choose a new empty
// directory for a separate demo group.
//
// Private round checkpoints stay in session.Memory for this online demo.
// See example/cold-frost for resumable signing across process restarts.
//
// Each Node is an independent party. The orchestrator here is a stand-in for
// whatever transport you use in production (HTTP, gRPC, message queue, etc.).
//
// Run from the repository root: go -C example/frost run .
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"

	"go-mpc-example/frost/node"
	"go-mpc-example/shared"

	"github.com/chrisalmeida/go-mpc/frost"
	"github.com/chrisalmeida/go-mpc/session"
)

const (
	threshold = 2
)

var allIDs = []int{1, 2, 3}
var shareDir = shared.DemoDirectory()
var demoEncryptor *shared.AESEncryptor
var demoStore = &shared.FileStore{Directory: shareDir}
var guards = make(map[int]*shared.Guard)

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
func round(id int, kind session.Kind, operation string, phase int, parties []int, compute session.Compute) []byte {
	op, err := guards[id].ID(kind, operation)
	must(err)
	output, err := guards[id].Advance(op, phase, parties, compute)
	must(err)
	if kind == session.Signing || phase == 1 {
		output, err = (frost.SessionCodec{Encryptor: demoEncryptor}).OpenOutput(output, frost.KeyBinding{PublicKey: []byte(guards[id].Scope.PublicKey), PartyID: id, Epoch: op.Epoch}, op, phase)
		must(err)
	}
	return output
}

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
	demoEncryptor = enc
	if err != nil {
		log.Fatalf("encryption key: %v", err)
	}
	if loaded {
		return loadShares(enc)
	}
	return generateAndSave(enc)
}

func loadShares(enc *shared.AESEncryptor) ([]*node.Node, []byte) {
	m, err := shared.LoadManifest(shareDir)
	must(err)
	if m.Protocol != "frost" {
		log.Fatal("wrong protocol in demo manifest")
	}
	nodes := make([]*node.Node, len(allIDs))
	for i, id := range allIDs {
		scope := session.Scope{Protocol: session.FROST, PublicKey: string(m.PublicKey), PartyID: id}
		key, err := session.InspectKey(context.Background(), demoStore, scope)
		must(err)
		state, err := frost.UnmarshalSignerEncrypted(key.Checkpoint, enc, frost.KeyBinding{PublicKey: m.PublicKey, PartyID: id, Epoch: key.Epoch})
		must(err)
		nodes[i] = &node.Node{ID: id, AllIDs: allIDs, Threshold: threshold, State: state}
		guards[id] = &shared.Guard{Store: demoStore, Scope: scope}
	}
	return nodes, m.PublicKey
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

	for _, n := range nodes {
		scope := session.Scope{Protocol: session.FROST, PublicKey: string(pubKey), PartyID: n.ID}
		checkpoint, err := frost.MarshalSignerEncrypted(n.State, enc)
		must(err)
		_, err = session.Initialize(context.Background(), demoStore, scope, 0, checkpoint)
		must(err)
		guards[n.ID] = &shared.Guard{Store: demoStore, Scope: scope}
	}
	must(shared.SaveManifest(shareDir, shared.Manifest{Protocol: "frost", PublicKey: pubKey, Parties: allIDs}))

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

// refresh runs each round through encrypted authoritative state and activates
// only after every participant has prepared its candidate in this demo.
func refresh(nodes []*node.Node) {
	operation := node.SessionID()
	codec := frost.SessionCodec{Encryptor: demoEncryptor}
	r1 := make(map[int]*frost.RefreshRound1Output)
	r2 := make(map[int]*frost.RefreshRound2Output)
	for _, n := range nodes {
		var out frost.RefreshRound1Output
		must(json.Unmarshal(round(n.ID, session.Refresh, operation, 1, allIDs, codec.Refresh(nil, nil)), &out))
		r1[n.ID] = &out
	}
	for _, n := range nodes {
		blob := round(n.ID, session.Refresh, operation, 2, allIDs, codec.Refresh(r1, nil))
		out, err := codec.OpenRefreshRound2(blob, n.State.Binding(), operation)
		must(err)
		r2[n.ID] = out
	}

	for _, n := range nodes {
		round(n.ID, session.Refresh, operation, 3, allIDs, codec.Refresh(r1, r2))
	}
	for _, n := range nodes {
		must(guards[n.ID].Activate(operation))
	}
	restored, _ := loadShares(demoEncryptor)
	for i := range nodes {
		*nodes[i] = *restored[i]
	}
}

// sign runs RFC 9591 through the guard with in-memory private checkpoints.
func sign(nodes []*node.Node, signers []int, message []byte) *frost.Signature {
	operation := node.SessionID()
	codec := frost.SessionCodec{Encryptor: demoEncryptor}
	commitments := make(map[int]*frost.NonceCommitment)
	shares := make(map[int]*frost.SignatureShare)
	for _, id := range signers {
		var out frost.NonceCommitment
		must(json.Unmarshal(round(id, session.Signing, operation, 1, signers, codec.Signing(nil)), &out))
		commitments[id] = &out
	}
	input := &frost.Round2Input{Message: message, AllCommitments: commitments}
	for _, id := range signers {
		var out frost.SignatureShare
		must(json.Unmarshal(round(id, session.Signing, operation, 2, signers, codec.Signing(input)), &out))
		shares[id] = &out
	}
	verification := make(map[int][]byte)
	for _, n := range nodes {
		verification[n.ID] = n.KeyShare().VerificationShare
	}
	sig, err := frost.Aggregate(commitments, shares, message, nodes[0].PublicKey(), verification, signers)
	must(err)
	return sig
}
