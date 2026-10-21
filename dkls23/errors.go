package dkls23

import (
	"fmt"
	"strings"
)

// Error categories for programmatic handling.
// Callers can use errors.As() to check the category:
//
//	var cheatErr *CheatingPartyError
//	if errors.As(err, &cheatErr) {
//	    // blacklist cheatErr.PartyIDs...
//	}
//
//	var inputErr *InvalidInputError
//	if errors.As(err, &inputErr) {
//	    // caller bug, don't retry
//	}

// CheatingPartyError indicates one or more parties failed verification checks.
// The protocol detected dishonest behaviour (bad Feldman, bad FCom, bad VOLE proof).
// Action: blacklist the listed parties; the protocol can continue without them
// if enough honest parties remain above the threshold.
type CheatingPartyError struct {
	PartyIDs []int
	Phase    string // e.g. "SignRound3", "DKGFinalize", "RefreshFinalize"
	Detail   string
}

func (e *CheatingPartyError) Error() string {
	return fmt.Sprintf("dkls23 %s: cheating detected from parties %v: %s", e.Phase, e.PartyIDs, e.Detail)
}

// InvalidInputError indicates the caller provided invalid arguments.
// This is a programming error — retrying with the same inputs will always fail.
type InvalidInputError struct {
	Phase  string
	Detail string
}

func (e *InvalidInputError) Error() string {
	return fmt.Sprintf("dkls23 %s: invalid input: %s", e.Phase, e.Detail)
}

// CorruptStateError indicates that internal state is inconsistent or corrupted.
// Action: halt the protocol, investigate, and potentially recover from backup.
type CorruptStateError struct {
	Phase  string
	Detail string
}

func (e *CorruptStateError) Error() string {
	return fmt.Sprintf("dkls23 %s: corrupt state: %s", e.Phase, e.Detail)
}

// SessionIDReusedError indicates that a signing round was invoked for a session
// id that this SignerSetup has already completed that round for (DKLS23
// Protocol 3.6 step 4: a request whose sigid is not fresh is ignored).
// Reusing a session id would reuse the session's OT-extension correlation
// and leak the signer's nonce; the call is rejected and nothing is computed.
// Action: start a new session with a fresh session id.
type SessionIDReusedError struct {
	SigID  string
	Phase  string
	Detail string
}

func (e *SessionIDReusedError) Error() string {
	return fmt.Sprintf("dkls23 %s: session id %q reused: %s", e.Phase, e.SigID, e.Detail)
}

// BlacklistedPartyError indicates an operation was rejected because one or more
// parties in the requested set have been blacklisted for prior cheating.
type BlacklistedPartyError struct {
	PartyIDs []int
	Phase    string
}

func (e *BlacklistedPartyError) Error() string {
	ids := make([]string, len(e.PartyIDs))
	for i, id := range e.PartyIDs {
		ids[i] = fmt.Sprintf("%d", id)
	}
	return fmt.Sprintf("dkls23 %s: blacklisted parties in signer set: [%s]", e.Phase, strings.Join(ids, ", "))
}
