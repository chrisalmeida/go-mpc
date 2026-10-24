// This example demonstrates a complete 3-of-3 DKLS23 threshold ECDSA flow:
//
//  1. Key Generation  — Feldman VSS DKG (commit-then-reveal), no trusted dealer
//  2. Pairwise Setup  — one-time base OTs + FZero seeds
//  3. Persistence     — encrypted setup and authoritative session progress
//  4. Signing         — 3-round threshold ECDSA with fresh OT extension and VOLE
//  5. Key Refresh     — prepare every party, activate, reload, and sign again
//
// Set MPC_WRAPPING_KEY to a 32-byte hex demo key and retain it between runs.
// MPC_DEMO_DIR selects the store directory (default shares/). The first run
// creates a group; subsequent runs reload it and skip DKG and pairwise setup.
// Choose a new empty directory for a separate demo group.
//
// Private round checkpoints stay in session.Memory for this online demo.
// See example/cold-dkls23 for resumable signing across process restarts.
// Run from the repository root: go -C example/dkls23 run .
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"

	"go-mpc-example/dkls23/node"
	"go-mpc-example/shared"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"

	"github.com/chrisalmeida/go-mpc/dkls23"
	"github.com/chrisalmeida/go-mpc/session"
)

const (
	threshold = 3
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
		output, err = (dkls23.SessionCodec{Encryptor: demoEncryptor}).OpenOutput(output, dkls23.KeyBinding{PublicKey: []byte(guards[id].Scope.PublicKey), PartyID: id, Epoch: op.Epoch}, op, phase)
		must(err)
	}
	return output
}

func main() {
	fmt.Println("DKLS23 Threshold ECDSA — 3-of-3 Demo")
	fmt.Println()

	nodes, pubKey, _ := loadOrGenerate()

	// ── Signing (before refresh) ────────────────────────────────────

	message := []byte("hello threshold ECDSA")
	fmt.Println("Phase: Signing (before refresh)")
	signAndPrint(nodes, pubKey, allIDs, message)

	// ── Key Refresh ─────────────────────────────────────────────────

	fmt.Println("Phase: Key Refresh")
	refresh(nodes)
	fmt.Println("  shares rotated, public key unchanged")
	// Activation has persisted the refreshed setup and advanced the epoch.
	fmt.Printf("  refreshed shares saved (epoch %d)\n", nodes[0].Epoch())
	fmt.Println()

	// ── Signing (after refresh) ─────────────────────────────────────

	fmt.Println("Phase: Signing (after refresh)")
	signAndPrint(nodes, pubKey, allIDs, message)

	fmt.Println("Done.")
}

// loadOrGenerate loads existing shares from disk or runs the full ceremony
// (DKG → pairwise setup → initialize the store) if no manifest exists.
func loadOrGenerate() (nodes []*node.Node, pubKey []byte, enc *shared.AESEncryptor) {
	enc, loaded, err := shared.LoadOrCreateKey(shareDir)
	demoEncryptor = enc
	if err != nil {
		log.Fatalf("encryption key: %v", err)
	}
	if loaded {
		nodes, pubKey = loadShares(enc)
		return nodes, pubKey, enc
	}
	nodes, pubKey = generateAndSave(enc)
	return nodes, pubKey, enc
}

func loadShares(enc *shared.AESEncryptor) ([]*node.Node, []byte) {
	m, err := shared.LoadManifest(shareDir)
	must(err)
	if m.Protocol != "dkls23" {
		log.Fatal("wrong protocol in demo manifest")
	}
	nodes := make([]*node.Node, len(allIDs))
	for i, id := range allIDs {
		scope := session.Scope{Protocol: session.DKLS23, PublicKey: string(m.PublicKey), PartyID: id}
		key, err := session.InspectKey(context.Background(), demoStore, scope)
		must(err)
		setup, err := dkls23.UnmarshalEncrypted(key.Checkpoint, enc, dkls23.KeyBinding{PublicKey: m.PublicKey, PartyID: id, Epoch: key.Epoch})
		must(err)
		nodes[i] = &node.Node{ID: id, AllIDs: allIDs, Threshold: threshold, Setup: setup}
		guards[id] = &shared.Guard{Store: demoStore, Scope: scope}
	}
	return nodes, m.PublicKey
}

// generateAndSave runs DKG and pairwise setup, then initializes the store.
func generateAndSave(enc *shared.AESEncryptor) ([]*node.Node, []byte) {
	// ── DKG ─────────────────────────────────────────────────────

	fmt.Println("Phase 1: Key Generation")

	nodes := make([]*node.Node, len(allIDs))
	for i, id := range allIDs {
		nodes[i] = node.New(id, allIDs, threshold)
	}

	allRound1 := make(map[int]*dkls23.DKGRound1Output)
	for _, n := range nodes {
		out, err := n.DKGRound1()
		if err != nil {
			log.Fatalf("DKG round 1 node %d: %v", n.ID, err)
		}
		allRound1[n.ID] = out
	}

	allRound2 := make(map[int]*dkls23.DKGRound2Output)
	for _, n := range nodes {
		out, err := n.DKGRound2(allRound1)
		if err != nil {
			log.Fatalf("DKG round 2 node %d: %v", n.ID, err)
		}
		allRound2[n.ID] = out
	}

	var pubKey []byte
	for _, n := range nodes {
		pk, err := n.DKGFinalize(allRound1, allRound2)
		if err != nil {
			log.Fatalf("DKG finalize node %d: %v", n.ID, err)
		}
		pubKey = pk
	}
	fmt.Printf("  public key: %s\n\n", hex.EncodeToString(pubKey))

	// ── Pairwise Setup ──────────────────────────────────────────

	fmt.Println("Phase 2: Pairwise Setup (one-time base OTs + FZero)")

	for i := 0; i < len(nodes); i++ {
		for j := i + 1; j < len(nodes); j++ {
			if err := nodes[i].SetupPairwiseWith(nodes[j]); err != nil {
				log.Fatalf("pairwise setup %d↔%d: %v", nodes[i].ID, nodes[j].ID, err)
			}
			fmt.Printf("  node %d ↔ node %d: base OTs + FZero established\n", nodes[i].ID, nodes[j].ID)
		}
	}
	fmt.Println()

	for _, n := range nodes {
		scope := session.Scope{Protocol: session.DKLS23, PublicKey: string(pubKey), PartyID: n.ID}
		checkpoint, err := dkls23.MarshalEncrypted(n.Setup, enc)
		must(err)
		_, err = session.Initialize(context.Background(), demoStore, scope, 0, checkpoint)
		must(err)
		guards[n.ID] = &shared.Guard{Store: demoStore, Scope: scope}
	}
	must(shared.SaveManifest(shareDir, shared.Manifest{Protocol: "dkls23", PublicKey: pubKey, Parties: allIDs}))

	return nodes, pubKey
}

// signAndPrint signs a message, verifies, and prints verification data for the online tool.
func signAndPrint(nodes []*node.Node, pubKey []byte, signers []int, message []byte) {
	fmt.Printf("  message: %q\n", message)

	r, s := sign(nodes, signers, message)

	fmt.Printf("  r: %s\n", hex.EncodeToString(r))
	fmt.Printf("  s: %s\n", hex.EncodeToString(s))

	if node.VerifySignature(pubKey, message, r, s) {
		fmt.Println("  signature valid")
	} else {
		log.Fatal("  signature verification FAILED")
	}

	parsedPub, err := btcec.ParsePubKey(pubKey)
	if err != nil {
		log.Fatalf("parse pubkey: %v", err)
	}
	var rScalar, sScalar btcec.ModNScalar
	rScalar.SetByteSlice(r)
	sScalar.SetByteSlice(s)
	derSig := ecdsa.NewSignature(&rScalar, &sScalar).Serialize()

	fmt.Println()
	fmt.Println("  Verify at: https://emn178.github.io/online-tools/ecdsa/verify/")
	fmt.Printf("  Public key (uncompressed): %s\n", hex.EncodeToString(parsedPub.SerializeUncompressed()))
	fmt.Printf("  Signature (DER): %s\n", hex.EncodeToString(derSig))
	fmt.Printf("  Message: %s\n", message)
	fmt.Println()
}

// refresh runs each round through encrypted authoritative state and activates
// only after every participant has prepared its candidate in this demo.
func refresh(nodes []*node.Node) {
	operation := node.SessionID()
	codec := dkls23.SessionCodec{Encryptor: demoEncryptor}
	r1 := make(map[int]*dkls23.RefreshRound1Output)
	r2 := make(map[int]*dkls23.RefreshRound2Output)
	for _, n := range nodes {
		var out dkls23.RefreshRound1Output
		must(json.Unmarshal(round(n.ID, session.Refresh, operation, 1, allIDs, codec.Refresh(nil, nil)), &out))
		r1[n.ID] = &out
	}
	for _, n := range nodes {
		blob := round(n.ID, session.Refresh, operation, 2, allIDs, codec.Refresh(r1, nil))
		out, err := codec.OpenRefreshRound2(blob, n.Setup.Binding(), operation)
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

// sign runs three guarded rounds; no private round state leaves a codec.
func sign(nodes []*node.Node, signers []int, message []byte) ([]byte, []byte) {
	operation := node.SessionID()
	codec := dkls23.SessionCodec{Encryptor: demoEncryptor}
	r1 := make(map[int]map[int]*dkls23.Round1Msg)
	r2 := make(map[int]map[int]*dkls23.Round2Msg)
	r3 := make(map[int]map[int]*dkls23.Round3Msg)
	for _, id := range signers {
		var out map[int]*dkls23.Round1Msg
		must(json.Unmarshal(round(id, session.Signing, operation, 1, signers, codec.Signing(dkls23.SessionSignInput{})), &out))
		r1[id] = out
	}
	for _, id := range signers {
		var out map[int]*dkls23.Round2Msg
		input := dkls23.SessionSignInput{Round1: routeMsgs(signers, id, r1), Message: message}
		must(json.Unmarshal(round(id, session.Signing, operation, 2, signers, codec.Signing(input)), &out))
		r2[id] = out
	}
	for _, id := range signers {
		var out map[int]*dkls23.Round3Msg
		input := dkls23.SessionSignInput{Round2: routeMsgs(signers, id, r2), Message: message}
		must(json.Unmarshal(round(id, session.Signing, operation, 3, signers, codec.Signing(input)), &out))
		r3[id] = out
	}
	points := make(map[int][]byte)
	fragments := make(map[int]*dkls23.Round3Msg)
	for _, id := range signers {
		for _, out := range r2[id] {
			points[id] = out.Decommitment
			break
		}
		fragments[id] = r3[id][signers[0]]
	}
	rx, err := dkls23.ComputeRx(points)
	must(err)
	own := fragments[signers[0]]
	var w, u btcec.ModNScalar
	w.SetByteSlice(own.W_i)
	u.SetByteSlice(own.U_i)
	var combiner *node.Node
	for _, n := range nodes {
		if n.ID == signers[0] {
			combiner = n
		}
	}
	r, s, err := combiner.SignCombine(&rx, &w, &u, fragments, message)
	must(err)
	return r, s
}

// routeMsgs collects inbound messages for myID from all other signers.
func routeMsgs[T any](signers []int, myID int, allMsgs map[int]map[int]T) map[int]T {
	m := make(map[int]T)
	for _, j := range signers {
		if j != myID {
			m[j] = allMsgs[j][myID]
		}
	}
	return m
}
