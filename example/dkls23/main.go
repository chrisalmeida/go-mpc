// This example demonstrates a complete 3-of-3 DKLS23 threshold ECDSA flow:
//
//  1. Key Generation  — Feldman VSS DKG (commit-then-reveal), no trusted dealer
//  2. Pairwise Setup  — one-time base OTs + FZero seeds
//  3. Signing         — 3-round threshold ECDSA; each session runs a fresh
//     OT extension and VOLE over the base OTs
//  4. Key Refresh     — rotate shares without changing the public key
//  5. Persistence     — encrypted key shares saved to disk and reloaded
//
// On the first run, all five phases execute and shares are saved to shares/.
// On subsequent runs, shares are loaded from disk — DKG and pairwise setup
// are skipped, and the public key stays the same.
//
// Delete the shares/ directory to start fresh.
//
// Run: cd example/dkls23 && go run .
package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"path/filepath"

	"go-mpc-example/dkls23/node"
	"go-mpc-example/shared"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"

	"github.com/chrisalmeida/go-mpc/dkls23"
)

const (
	shareDir  = "shares"
	threshold = 3
)

var allIDs = []int{1, 2, 3}

func main() {
	fmt.Println("DKLS23 Threshold ECDSA — 3-of-3 Demo")
	fmt.Println()

	nodes, pubKey, enc := loadOrGenerate()

	// ── Signing (before refresh) ────────────────────────────────────

	message := []byte("hello threshold ECDSA")
	fmt.Println("Phase: Signing (before refresh)")
	signAndPrint(nodes, pubKey, allIDs, message)

	// ── Key Refresh ─────────────────────────────────────────────────

	fmt.Println("Phase: Key Refresh")
	refresh(nodes)
	fmt.Println("  shares rotated, public key unchanged")
	// Persist the refreshed shares: the pre-refresh shares on disk are now
	// stale and must not be used again.
	saveShares(nodes, enc)
	fmt.Printf("  refreshed shares saved (epoch %d)\n", nodes[0].Epoch())
	fmt.Println()

	// ── Signing (after refresh) ─────────────────────────────────────

	fmt.Println("Phase: Signing (after refresh)")
	signAndPrint(nodes, pubKey, allIDs, message)

	fmt.Println("Done.")
}

// loadOrGenerate loads existing shares from disk or runs the full ceremony
// (DKG → pairwise setup → refresh → persist) if no shares exist.
func loadOrGenerate() (nodes []*node.Node, pubKey []byte, enc *shared.AESEncryptor) {
	enc, loaded, err := shared.LoadOrCreateKey(shareDir)
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

// saveShares encrypts and writes every node's SignerSetup to disk.
func saveShares(nodes []*node.Node, enc *shared.AESEncryptor) {
	for _, n := range nodes {
		p := filepath.Join(shareDir, fmt.Sprintf("node-%d.enc", n.ID))
		if err := n.SaveSetup(p, enc); err != nil {
			log.Fatalf("save node %d: %v", n.ID, err)
		}
	}
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
		fmt.Printf("  node %d loaded (epoch %d)\n", n.ID, n.Epoch())
	}

	pubKey := nodes[0].PublicKey()
	fmt.Printf("  public key: %s\n\n", hex.EncodeToString(pubKey))
	return nodes, pubKey
}

// generateAndSave runs DKG, pairwise setup, refresh, and saves to disk.
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

	// ── Persist ─────────────────────────────────────────────────

	fmt.Println("Phase 3: Saving Key Shares")

	saveShares(nodes, enc)
	for _, n := range nodes {
		fmt.Printf("  node %d → %s\n", n.ID, filepath.Join(shareDir, fmt.Sprintf("node-%d.enc", n.ID)))
	}
	fmt.Println()

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

// refresh runs the 2-round key refresh protocol across all nodes.
func refresh(nodes []*node.Node) {
	allRefR1 := make(map[int]*dkls23.RefreshRound1Output)
	for _, n := range nodes {
		out, err := n.RefreshRound1()
		if err != nil {
			log.Fatalf("refresh round 1 node %d: %v", n.ID, err)
		}
		allRefR1[n.ID] = out
	}

	allRefR2 := make(map[int]*dkls23.RefreshRound2Output)
	for _, n := range nodes {
		out, err := n.RefreshRound2(allRefR1)
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

// sign runs the 3-round signing protocol across all nodes and returns (r, s).
func sign(nodes []*node.Node, signers []int, message []byte) (r, s []byte) {
	nodeMap := make(map[int]*node.Node, len(nodes))
	for _, n := range nodes {
		nodeMap[n.ID] = n
	}

	sigID := node.SessionID()

	// Round 1: nonce commitments.
	r1States := make(map[int]*dkls23.Round1State)
	r1Msgs := make(map[int]map[int]*dkls23.Round1Msg)
	for _, n := range nodes {
		st, msgs, err := n.SignRound1(sigID, signers)
		if err != nil {
			log.Fatalf("sign round 1 node %d: %v", n.ID, err)
		}
		r1States[n.ID] = st
		r1Msgs[n.ID] = msgs
	}

	// Round 2: VOLE multiply, decommit nonces.
	r2States := make(map[int]*dkls23.Round2State)
	r2Msgs := make(map[int]map[int]*dkls23.Round2Msg)
	for _, n := range nodes {
		in := routeMsgs(signers, n.ID, r1Msgs)
		st, msgs, err := n.SignRound2(r1States[n.ID], in)
		if err != nil {
			log.Fatalf("sign round 2 node %d: %v", n.ID, err)
		}
		r2States[n.ID] = st
		r2Msgs[n.ID] = msgs
	}

	// Round 3: consistency checks, compute signature fragments.
	r3Frags := make(map[int]map[int]*dkls23.Round3Msg)
	for _, n := range nodes {
		in := routeMsgs(signers, n.ID, r2Msgs)
		frags, err := n.SignRound3(r2States[n.ID], message, in)
		if err != nil {
			log.Fatalf("sign round 3 node %d: %v", n.ID, err)
		}
		r3Frags[n.ID] = frags
	}

	// Combine: node 1 aggregates fragments into (r, s).
	combiner := nodeMap[1]
	rx := node.ComputeRx(signers, r2States)
	myFrag := r3Frags[1][1]
	var myW, myU btcec.ModNScalar
	myW.SetByteSlice(myFrag.W_i)
	myU.SetByteSlice(myFrag.U_i)

	allFrags := make(map[int]*dkls23.Round3Msg)
	for _, j := range signers {
		if j != 1 {
			allFrags[j] = r3Frags[j][1]
		}
	}

	r, s, err := combiner.SignCombine(&rx, &myW, &myU, allFrags, message)
	if err != nil {
		log.Fatalf("sign combine: %v", err)
	}
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
