// cold-frost demonstrates two offline devices exchanging public message files.
// Each command is a separate process; no private nonce object crosses a process
// boundary. The init command is a colocated demo ceremony, not a custody design.
// Set MPC_WRAPPING_KEY before init and retain it for subsequent device commands.
// Run with --help for commands; README.md contains a manual file-transfer flow.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/chrisalmeida/go-mpc/frost"
	"github.com/chrisalmeida/go-mpc/session"
	"go-mpc-example/frost/node"
	"go-mpc-example/shared"
)

type configuration struct {
	PublicKey          []byte
	PartyID            int
	Epoch              int
	Participants       []int
	VerificationShares map[int][]byte
}
type signingRequest struct {
	OperationID string
	Epoch       int
	Message     []byte
	Commitments map[int]*frost.NonceCommitment
}

func write(path string, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}
func read(path string, value any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, value)
}

func initialize(root string) error {
	if entries, err := os.ReadDir(root); err == nil && len(entries) > 0 {
		return fmt.Errorf("demo root must be empty")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return err
	}
	ids := []int{1, 2}
	nodes := make([]*node.Node, 2)
	// Both parties agree on one fresh DKG context.
	contextID := []byte("cold demo DKG " + node.SessionID())
	nodes[0] = node.New(1, ids, 2, contextID)
	nodes[1] = node.New(2, ids, 2, contextID)
	r1 := make(map[int]*frost.DKGRound1Output)
	r2 := make(map[int]*frost.DKGRound2Output)
	for _, n := range nodes {
		out, err := n.DKGRound1()
		if err != nil {
			return err
		}
		r1[n.ID] = out
	}
	for _, n := range nodes {
		out, err := n.DKGRound2(r1)
		if err != nil {
			return err
		}
		r2[n.ID] = out
	}
	for _, n := range nodes {
		if err := n.DKGFinalize(r1, r2); err != nil {
			return err
		}
	}
	verification := make(map[int][]byte)
	for _, n := range nodes {
		verification[n.ID] = n.KeyShare().VerificationShare
	}
	for _, n := range nodes {
		dir := filepath.Join(root, "device-"+strconv.Itoa(n.ID))
		enc, _, err := shared.LoadOrCreateKey(dir)
		if err != nil {
			return err
		}
		cfg := configuration{PublicKey: n.PublicKey(), PartyID: n.ID, Participants: ids, VerificationShares: verification}
		blob, err := frost.MarshalSignerEncrypted(n.State, enc)
		if err != nil {
			return err
		}
		scope := session.Scope{Protocol: session.FROST, PublicKey: string(cfg.PublicKey), PartyID: n.ID}
		if _, err := session.Initialize(context.Background(), &shared.FileStore{Directory: dir}, scope, 0, blob); err != nil {
			return err
		}
		if err := write(filepath.Join(dir, "config.json"), cfg); err != nil {
			return err
		}
		if err := shared.SaveManifest(dir, shared.Manifest{Protocol: "frost", PublicKey: cfg.PublicKey, Parties: ids}); err != nil {
			return err
		}
	}
	return write(filepath.Join(root, "group.json"), configuration{PublicKey: nodes[0].PublicKey(), Participants: ids, VerificationShares: verification})
}

func deviceRound(dir, operation string, round int, requestPath, outputPath string) error {
	var cfg configuration
	if err := read(filepath.Join(dir, "config.json"), &cfg); err != nil {
		return err
	}
	enc, _, err := shared.LoadOrCreateKey(dir)
	if err != nil {
		return err
	}
	store := &shared.FileStore{Directory: dir}
	scope := session.Scope{Protocol: session.FROST, PublicKey: string(cfg.PublicKey), PartyID: cfg.PartyID}
	key, err := session.InspectKey(context.Background(), store, scope)
	if err != nil {
		return err
	}
	var input *frost.Round2Input
	if round == 2 {
		var req signingRequest
		if err := read(requestPath, &req); err != nil {
			return err
		}
		if req.OperationID != operation || req.Epoch != key.Epoch {
			return fmt.Errorf("request operation or epoch differs")
		}
		input = &frost.Round2Input{Message: req.Message, AllCommitments: req.Commitments}
	}
	id := session.ID{Kind: session.Signing, Epoch: key.Epoch, Value: operation}
	// A command can be retried after output-file failure or lost acknowledgement.
	// Recover the identical committed bytes; never compute a completed round again.
	output, err := session.Output(context.Background(), store, scope, id, round)
	if errors.Is(err, session.ErrMissing) {
		receipt, advanceErr := session.Advance(context.Background(), store, scope, session.Request{Version: key.Version, ID: id, Round: round, Participants: cfg.Participants}, (frost.SessionCodec{Encryptor: enc}).Signing(input))
		if advanceErr != nil {
			return advanceErr
		}
		output = receipt.Output
	} else if err != nil {
		return err
	}
	plaintext, err := (frost.SessionCodec{Encryptor: enc}).OpenOutput(output, frost.KeyBinding{PublicKey: cfg.PublicKey, PartyID: cfg.PartyID, Epoch: key.Epoch}, id, round)
	if err != nil {
		return err
	}
	defer clear(plaintext)
	return os.WriteFile(outputPath, plaintext, 0600)
}

// makeRequest associates commitment files with the group's configured participant
// order. The caller authenticates their origins and operation before delivery.
func makeRequest(root, operation, messagePath, first, second, output string) error {
	var cfg configuration
	if err := read(filepath.Join(root, "group.json"), &cfg); err != nil {
		return err
	}
	if operation == "" || len(cfg.Participants) != 2 || cfg.Participants[0] == cfg.Participants[1] {
		return fmt.Errorf("expected a nonempty operation and two distinct participants")
	}
	message, err := os.ReadFile(messagePath)
	if err != nil {
		return err
	}
	commitments := make(map[int]*frost.NonceCommitment)
	for i, path := range []string{first, second} {
		var commitment frost.NonceCommitment
		if err := read(path, &commitment); err != nil {
			return err
		}
		commitments[cfg.Participants[i]] = &commitment
	}
	return write(output, signingRequest{OperationID: operation, Epoch: cfg.Epoch, Message: message, Commitments: commitments})
}

func aggregate(root, requestPath, first, second, output string) error {
	var cfg configuration
	var req signingRequest
	if err := read(filepath.Join(root, "group.json"), &cfg); err != nil {
		return err
	}
	if err := read(requestPath, &req); err != nil {
		return err
	}
	shares := make(map[int]*frost.SignatureShare)
	for _, path := range []string{first, second} {
		var share frost.SignatureShare
		if err := read(path, &share); err != nil {
			return err
		}
		if shares[share.SignerID] != nil {
			return fmt.Errorf("duplicate signer")
		}
		shares[share.SignerID] = &share
	}
	sig, err := frost.Aggregate(req.Commitments, shares, req.Message, cfg.PublicKey, cfg.VerificationShares, cfg.Participants)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(cfg.PublicKey), req.Message, sig.Bytes()) {
		return fmt.Errorf("independent Ed25519 verification failed")
	}
	if err := os.WriteFile(output, sig.Bytes(), 0600); err != nil {
		return err
	}
	fmt.Println("Cold FROST signature verified with crypto/ed25519 after process restarts.")
	return nil
}

func demo(root string) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	run := func(args ...string) error {
		cmd := exec.Command(executable, args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
	if err := run("init", root); err != nil {
		return err
	}
	operation := node.SessionID()
	for _, id := range []int{1, 2} {
		out := filepath.Join(root, fmt.Sprintf("commitment-%d.json", id))
		if err := run("commit", filepath.Join(root, fmt.Sprintf("device-%d", id)), operation, out); err != nil {
			return err
		}
	}
	requestPath := filepath.Join(root, "request.json")
	messagePath := filepath.Join(root, "message.txt")
	if err := os.WriteFile(messagePath, []byte("offline file transfer signing"), 0600); err != nil {
		return err
	}
	if err := run("request", root, operation, messagePath, filepath.Join(root, "commitment-1.json"), filepath.Join(root, "commitment-2.json"), requestPath); err != nil {
		return err
	}
	for _, id := range []int{1, 2} {
		if err := run("sign", filepath.Join(root, fmt.Sprintf("device-%d", id)), operation, requestPath, filepath.Join(root, fmt.Sprintf("share-%d.json", id))); err != nil {
			return err
		}
	}
	return run("aggregate", root, requestPath, filepath.Join(root, "share-1.json"), filepath.Join(root, "share-2.json"), filepath.Join(root, "signature.bin"))
}

const usage = `usage: cold-frost COMMAND ...
  demo ROOT
  init ROOT
  commit DEVICE OP OUT
  request ROOT OP MESSAGE_FILE COMMITMENT1 COMMITMENT2 OUT
  sign DEVICE OP REQUEST OUT
  aggregate ROOT REQUEST SHARE1 SHARE2 OUT

init requires an empty directory. request takes commitments in participant order
(device-1, device-2). Set MPC_WRAPPING_KEY to the same 64 hex characters for each
device command in this demo. Retry the same operation to recover committed output;
use a fresh operation ID for a new signature`

func run(args []string) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Println(usage)
		return nil
	case "demo":
		if len(args) == 2 {
			return demo(args[1])
		}
	case "init":
		if len(args) == 2 {
			return initialize(args[1])
		}
	case "commit":
		if len(args) == 4 {
			return deviceRound(args[1], args[2], 1, "", args[3])
		}
	case "sign":
		if len(args) == 5 {
			return deviceRound(args[1], args[2], 2, args[3], args[4])
		}
	case "request":
		if len(args) == 7 {
			return makeRequest(args[1], args[2], args[3], args[4], args[5], args[6])
		}
	case "aggregate":
		if len(args) == 6 {
			return aggregate(args[1], args[2], args[3], args[4], args[5])
		}
	}
	return fmt.Errorf("invalid command arguments\n%s", usage)
}
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
