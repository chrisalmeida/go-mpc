// cold-dkls23 demonstrates 3-of-3 offline ECDSA signing. Each device command
// restores encrypted state, commits one round and exits. The coordinator routes
// per-recipient protocol messages; private round state stays in each device's
// store. File transport must be authenticated and confidential by the caller.
// init is a colocated demo ceremony. See README.md and --help for usage.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/chrisalmeida/go-mpc/dkls23"
	"github.com/chrisalmeida/go-mpc/session"
	"go-mpc-example/dkls23/node"
	"go-mpc-example/shared"
)

type configuration struct {
	PublicKey    []byte
	PartyID      int
	Epoch        int
	Participants []int
}

type roundRequest struct {
	PublicKey   []byte
	OperationID string
	Epoch       int
	Round       int
	Input       dkls23.SessionSignInput
}

// roundOutput wraps unchanged protocol messages with demo routing metadata.
// These fields help catch file mixups; they do not authenticate the sender.
type roundOutput struct {
	PublicKey   []byte
	OperationID string
	Epoch       int
	Round       int
	PartyID     int
	Messages    json.RawMessage
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

func roundPath(root string, round, party int) string {
	return filepath.Join(root, fmt.Sprintf("round-%d-%d.json", round, party))
}

func requestPath(root string, round, party int) string {
	return filepath.Join(root, fmt.Sprintf("request-%d-%d.json", round, party))
}

func initialize(root string) error {
	if entries, err := os.ReadDir(root); err == nil && len(entries) > 0 {
		return fmt.Errorf("demo root must be empty")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return err
	}
	ids := []int{1, 2, 3}
	nodes := make([]*node.Node, len(ids))
	r1 := make(map[int]*dkls23.DKGRound1Output)
	r2 := make(map[int]*dkls23.DKGRound2Output)
	for i, id := range ids {
		nodes[i] = node.New(id, ids, len(ids))
		out, err := nodes[i].DKGRound1()
		if err != nil {
			return err
		}
		r1[id] = out
	}
	for _, n := range nodes {
		out, err := n.DKGRound2(r1)
		if err != nil {
			return err
		}
		r2[n.ID] = out
	}
	for _, n := range nodes {
		if _, err := n.DKGFinalize(r1, r2); err != nil {
			return err
		}
	}
	for i, n := range nodes {
		for j := i + 1; j < len(nodes); j++ {
			if err := n.SetupPairwiseWith(nodes[j]); err != nil {
				return err
			}
		}
	}
	for _, n := range nodes {
		dir := filepath.Join(root, "device-"+strconv.Itoa(n.ID))
		enc, _, err := shared.LoadOrCreateKey(dir)
		if err != nil {
			return err
		}
		blob, err := dkls23.MarshalEncrypted(n.Setup, enc)
		if err != nil {
			return err
		}
		cfg := configuration{PublicKey: n.Setup.PubKey, PartyID: n.ID, Participants: ids}
		scope := session.Scope{Protocol: session.DKLS23, PublicKey: string(cfg.PublicKey), PartyID: n.ID}
		if _, err := session.Initialize(context.Background(), &shared.FileStore{Directory: dir}, scope, 0, blob); err != nil {
			return err
		}
		if err := write(filepath.Join(dir, "config.json"), cfg); err != nil {
			return err
		}
		if err := shared.SaveManifest(dir, shared.Manifest{Protocol: "dkls23", PublicKey: cfg.PublicKey, Parties: ids}); err != nil {
			return err
		}
	}
	return write(filepath.Join(root, "group.json"), configuration{PublicKey: nodes[0].Setup.PubKey, Participants: ids})
}

// loadRound checks the demo routing metadata before decoding protocol messages.
func loadRound[T any](root, operation string, cfg configuration, round int) (map[int]map[int]*T, error) {
	all := make(map[int]map[int]*T)
	for _, id := range cfg.Participants {
		var out roundOutput
		if err := read(roundPath(root, round, id), &out); err != nil {
			return nil, err
		}
		if !bytes.Equal(out.PublicKey, cfg.PublicKey) || out.OperationID != operation || out.Epoch != cfg.Epoch || out.Round != round || out.PartyID != id {
			return nil, fmt.Errorf("round %d party %d: mismatched output routing metadata", round, id)
		}
		var messages map[int]*T
		if err := json.Unmarshal(out.Messages, &messages); err != nil {
			return nil, err
		}
		for _, recipient := range cfg.Participants {
			if (recipient != id || round == 3) && messages[recipient] == nil {
				return nil, fmt.Errorf("round %d party %d: missing message for %d", round, id, recipient)
			}
		}
		all[id] = messages
	}
	return all, nil
}

func inbound[T any](all map[int]map[int]*T, party int) map[int]*T {
	messages := make(map[int]*T)
	for sender, outputs := range all {
		if sender != party {
			messages[sender] = outputs[party]
		}
	}
	return messages
}

// makeRequests writes only each recipient's inbound messages into its request.
// The same chosen message is supplied at rounds 2 and 3. The protocol uses it
// cryptographically at round 3; approval of that message remains the caller's.
func makeRequests(root, operation string, round int, messagePath string) error {
	if operation == "" || round < 1 || round > 3 {
		return fmt.Errorf("expected a nonempty operation and round 1, 2 or 3")
	}
	var cfg configuration
	if err := read(filepath.Join(root, "group.json"), &cfg); err != nil {
		return err
	}
	message, err := os.ReadFile(messagePath)
	if err != nil {
		return err
	}
	var r1 map[int]map[int]*dkls23.Round1Msg
	var r2 map[int]map[int]*dkls23.Round2Msg
	if round == 2 {
		r1, err = loadRound[dkls23.Round1Msg](root, operation, cfg, 1)
	}
	if round == 3 {
		r2, err = loadRound[dkls23.Round2Msg](root, operation, cfg, 2)
	}
	if err != nil {
		return err
	}
	for _, id := range cfg.Participants {
		input := dkls23.SessionSignInput{Message: message}
		if round == 2 {
			input.Round1 = inbound(r1, id)
		}
		if round == 3 {
			input.Round2 = inbound(r2, id)
		}
		req := roundRequest{PublicKey: cfg.PublicKey, OperationID: operation, Epoch: cfg.Epoch, Round: round, Input: input}
		if err := write(requestPath(root, round, id), req); err != nil {
			return err
		}
	}
	return nil
}

func deviceRound(dir, inputPath, outputPath string) error {
	var cfg configuration
	var req roundRequest
	if err := read(filepath.Join(dir, "config.json"), &cfg); err != nil {
		return err
	}
	if err := read(inputPath, &req); err != nil {
		return err
	}
	if !bytes.Equal(req.PublicKey, cfg.PublicKey) || req.OperationID == "" || req.Round < 1 || req.Round > 3 {
		return fmt.Errorf("invalid request binding, operation or round")
	}
	enc, _, err := shared.LoadOrCreateKey(dir)
	if err != nil {
		return err
	}
	store := &shared.FileStore{Directory: dir}
	scope := session.Scope{Protocol: session.DKLS23, PublicKey: string(cfg.PublicKey), PartyID: cfg.PartyID}
	ctx := context.Background()
	key, err := session.InspectKey(ctx, store, scope)
	if err != nil {
		return err
	}
	if req.Epoch != key.Epoch {
		return fmt.Errorf("request epoch differs from the authoritative key")
	}
	id := session.ID{Kind: session.Signing, Epoch: key.Epoch, Value: req.OperationID}
	codec := dkls23.SessionCodec{Encryptor: enc}
	// Retry retrieves the committed ciphertext even if an earlier command could
	// not deliver its output file. It does not run the signing round again.
	output, err := session.Output(ctx, store, scope, id, req.Round)
	if errors.Is(err, session.ErrMissing) {
		receipt, advanceErr := session.Advance(ctx, store, scope, session.Request{Version: key.Version, ID: id, Round: req.Round, Participants: cfg.Participants}, codec.Signing(req.Input))
		if advanceErr != nil {
			return advanceErr
		}
		output = receipt.Output
	} else if err != nil {
		return err
	}
	plaintext, err := codec.OpenOutput(output, dkls23.KeyBinding{PublicKey: cfg.PublicKey, PartyID: cfg.PartyID, Epoch: key.Epoch}, id, req.Round)
	if err != nil {
		return err
	}
	defer clear(plaintext)
	return write(outputPath, roundOutput{PublicKey: cfg.PublicKey, OperationID: id.Value, Epoch: id.Epoch, Round: req.Round, PartyID: cfg.PartyID, Messages: plaintext})
}

func combine(root, operation, messagePath, output string) error {
	var cfg configuration
	if err := read(filepath.Join(root, "group.json"), &cfg); err != nil {
		return err
	}
	if len(cfg.Participants) != 3 {
		return fmt.Errorf("this demo requires three participants")
	}
	message, err := os.ReadFile(messagePath)
	if err != nil {
		return err
	}
	r2, err := loadRound[dkls23.Round2Msg](root, operation, cfg, 2)
	if err != nil {
		return err
	}
	r3, err := loadRound[dkls23.Round3Msg](root, operation, cfg, 3)
	if err != nil {
		return err
	}
	points := make(map[int][]byte)
	fragments := make(map[int]*dkls23.Round3Msg)
	combiner := cfg.Participants[0]
	for _, id := range cfg.Participants {
		for _, recipient := range cfg.Participants {
			if recipient != id {
				points[id] = r2[id][recipient].Decommitment
				break
			}
		}
		fragments[id] = r3[id][combiner]
	}
	rx, err := dkls23.ComputeRx(points)
	if err != nil {
		return err
	}
	var w, u btcec.ModNScalar
	w.SetByteSlice(fragments[combiner].W_i)
	u.SetByteSlice(fragments[combiner].U_i)
	// SignCombine reads only MyID and PubKey from setup: the coordinator does
	// not load a secret share or private checkpoint to combine public fragments.
	publicSetup := &dkls23.SignerSetup{MyID: combiner, PubKey: cfg.PublicKey}
	r, s, err := dkls23.SignCombine(publicSetup, &rx, &w, &u, fragments, message)
	if err != nil {
		return err
	}
	if !node.VerifySignature(cfg.PublicKey, message, r, s) {
		return fmt.Errorf("independent ECDSA verification failed")
	}
	var rScalar, sScalar btcec.ModNScalar
	rScalar.SetByteSlice(r)
	sScalar.SetByteSlice(s)
	if err := os.WriteFile(output, ecdsa.NewSignature(&rScalar, &sScalar).Serialize(), 0600); err != nil {
		return err
	}
	fmt.Println("Cold DKLS23 ECDSA signature verified after process restarts (DER, SHA-256 message hash).")
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
	messagePath := filepath.Join(root, "message.txt")
	if err := os.WriteFile(messagePath, []byte("offline file transfer signing"), 0600); err != nil {
		return err
	}
	for round := 1; round <= 3; round++ {
		if err := run("request", root, operation, strconv.Itoa(round), messagePath); err != nil {
			return err
		}
		for _, id := range []int{1, 2, 3} {
			if err := run("round", filepath.Join(root, "device-"+strconv.Itoa(id)), requestPath(root, round, id), roundPath(root, round, id)); err != nil {
				return err
			}
		}
	}
	return run("combine", root, operation, messagePath, filepath.Join(root, "signature.der"))
}

const usage = `usage: cold-dkls23 COMMAND ...
  demo ROOT
  init ROOT
  request ROOT OP ROUND MESSAGE_FILE
  round DEVICE REQUEST OUT
  combine ROOT OP MESSAGE_FILE OUT

init requires an empty directory. request creates request-ROUND-PARTY.json files
from round-(ROUND-1)-PARTY.json replies in ROOT. Use rounds 1, 2, 3 in order and
write each device reply to round-ROUND-PARTY.json. Set MPC_WRAPPING_KEY to the same
64 hex characters for each device command in this demo. Retry the same operation
to recover committed output; use a fresh operation ID for a new signature`

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
	case "request":
		if len(args) == 5 {
			round, err := strconv.Atoi(args[3])
			if err != nil {
				return err
			}
			return makeRequests(args[1], args[2], round, args[4])
		}
	case "round":
		if len(args) == 4 {
			return deviceRound(args[1], args[2], args[3])
		}
	case "combine":
		if len(args) == 5 {
			return combine(args[1], args[2], args[3], args[4])
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
