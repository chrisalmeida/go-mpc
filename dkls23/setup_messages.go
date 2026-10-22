package dkls23

import "encoding/json"

// Pairwise setup message types for network-based base-OT + FZero establishment.
//
// In the example code, SetupPairwiseWith passes values directly between two
// in-process Node pointers. In production, the two nodes are separate processes
// and exchange these messages over the network.
//
// Per DKLS23 §8.1-8.2, the one-time setup for one directed VOLE pair (A→B,
// where A is Alice and B is Bob) consists only of the λc base OTs, realized
// by the two-round Masny-Rindal endemic OT (MR19) in ot.go. Alice is the
// base-OT receiver (choice bits sigma) and speaks first; Bob is the base-OT
// sender. The OT extension batch itself is NOT part of setup: Functionality
// 5.1 (FEOTE) requires a fresh session id per batch, so a new extension batch
// is run inside every signing session (see SignRound1 / SignRound2). The
// setup flow is:
//
//	Step 1: A → B:  BaseOTReceiverMsg     (A's LambdaC (r_0, r_1) pairs, from BaseOTReceiverRound1)
//	Step 2: B → A:  BaseOTSenderMsg       (B's LambdaC (m_{B,0}, m_{B,1}) pairs, from BaseOTSenderRound2;
//	                                       B derives both seed pairs here and A derives her seeds
//	                                       on receipt with BaseOTReceiverFinalize)
//	Step 3: A → B:  FZeroCommitMsg        (A's seed commitment)
//	        B → A:  FZeroCommitMsg        (B's seed commitment)
//	Step 4: A → B:  FZeroRevealMsg        (A's seed + salt)
//	        B → A:  FZeroRevealMsg        (B's seed + salt)
//
// For a bidirectional VOLE (required for signing), steps 1-2 run twice
// with swapped roles.  Steps 3-4 run once per pair.
//
// After step 2, Alice stores a BaseOTReceiverSeeds in SignerSetup.AliceBaseOT
// and Bob stores a BaseOTSenderSeeds in SignerSetup.BobBaseOT. The base-OT
// message types BaseOTReceiverMsg and BaseOTSenderMsg are defined in ot.go
// next to the protocol; the FZero message types are defined below.

// FZeroCommitMsg is sent by each party in step 3 of FZero setup.
type FZeroCommitMsg struct {
	// Commitment is FCom(seed): SHA-256(seed || salt).
	Commitment [32]byte `json:"commitment"`
}

// FZeroRevealMsg is sent by each party in step 4 of FZero setup.
type FZeroRevealMsg struct {
	// Seed is the 16-byte seed committed in FZeroCommitMsg.
	Seed [16]byte `json:"seed"`
	// Salt is the 32-byte FCom salt for the commitment.
	Salt [SaltLen]byte `json:"salt"`
}

// --- JSON encoding for setup messages ---

type fzeroCommitMsgJSON struct {
	Commitment string `json:"commitment"`
}

func (m *FZeroCommitMsg) MarshalJSON() ([]byte, error) {
	return json.Marshal(fzeroCommitMsgJSON{
		Commitment: bytesToHex(m.Commitment[:]),
	})
}

func (m *FZeroCommitMsg) UnmarshalJSON(data []byte) error {
	next := *m
	var j fzeroCommitMsgJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	var err error
	next.Commitment, err = hexToFixed32(j.Commitment)
	if err != nil {
		return err
	}
	*m = next
	return nil
}

type fzeroRevealMsgJSON struct {
	Seed string `json:"seed"`
	Salt string `json:"salt"`
}

func (m *FZeroRevealMsg) MarshalJSON() ([]byte, error) {
	return json.Marshal(fzeroRevealMsgJSON{
		Seed: bytesToHex(m.Seed[:]),
		Salt: bytesToHex(m.Salt[:]),
	})
}

func (m *FZeroRevealMsg) UnmarshalJSON(data []byte) error {
	next := *m
	var j fzeroRevealMsgJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	var err error
	next.Seed, err = hexToFixed16(j.Seed)
	if err != nil {
		return err
	}
	next.Salt, err = hexToFixed32(j.Salt)
	if err != nil {
		return err
	}
	*m = next
	return nil
}
