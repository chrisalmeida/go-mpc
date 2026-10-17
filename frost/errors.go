package frost

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

// CheatingPartyError indicates that messages attributed to one or more parties
// failed verification (a DKG proof of knowledge, a Feldman or hash commitment,
// a refresh share, or a signature share). Action: abort the session.
//
// Whether to also blacklist PartyIDs is an application decision. The
// attribution is only as good as the channel: RFC 9591 Section 5.4 states
// that "FROST assumes the network channel is authenticated to identify the
// signer that misbehaved". For Aggregate in particular, an equivocating
// Coordinator can make an honest signer's share fail verification, so see
// the caveats on Aggregate and SignerState.Blacklist before blacklisting
// automatically. The protocol can continue without the excluded parties if
// enough honest parties remain above the threshold.
type CheatingPartyError struct {
	PartyIDs []int
	Phase    string // e.g. "DKGFinalize", "Aggregate"
	Detail   string
}

func (e *CheatingPartyError) Error() string {
	return fmt.Sprintf("frost %s: cheating detected from parties %v: %s", e.Phase, e.PartyIDs, e.Detail)
}

// InvalidInputError indicates the caller provided invalid arguments.
// This is a programming error — retrying with the same inputs will always fail.
type InvalidInputError struct {
	Phase  string
	Detail string
}

func (e *InvalidInputError) Error() string {
	return fmt.Sprintf("frost %s: invalid input: %s", e.Phase, e.Detail)
}

// CorruptStateError indicates that internal state is inconsistent or corrupted.
// Action: halt the protocol, investigate, and potentially recover from backup.
type CorruptStateError struct {
	Phase  string
	Detail string
}

func (e *CorruptStateError) Error() string {
	return fmt.Sprintf("frost %s: corrupt state: %s", e.Phase, e.Detail)
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
	return fmt.Sprintf("frost %s: blacklisted parties in signer set: [%s]", e.Phase, strings.Join(ids, ", "))
}
