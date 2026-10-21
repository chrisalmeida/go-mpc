package dkls23

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheatingPartyErrorMessage(t *testing.T) {
	err := &CheatingPartyError{
		PartyIDs: []int{2, 3},
		Phase:    "SignRound3",
		Detail:   "verification checks failed",
	}
	msg := err.Error()
	require.Contains(t, msg, "SignRound3")
	require.Contains(t, msg, "[2 3]")
	require.Contains(t, msg, "verification checks failed")
}

func TestInvalidInputErrorMessage(t *testing.T) {
	err := &InvalidInputError{Phase: "SignRound1", Detail: "signers is empty"}
	require.Contains(t, err.Error(), "SignRound1")
	require.Contains(t, err.Error(), "signers is empty")
}

func TestCorruptStateErrorMessage(t *testing.T) {
	err := &CorruptStateError{Phase: "SignRound3", Detail: "pk mismatch"}
	require.Contains(t, err.Error(), "corrupt state")
	require.Contains(t, err.Error(), "pk mismatch")
}

func TestSessionIDReusedErrorMessage(t *testing.T) {
	err := &SessionIDReusedError{SigID: "abc", Phase: "SignRound2", Detail: "round 2 already completed for this session"}
	require.Contains(t, err.Error(), "SignRound2")
	require.Contains(t, err.Error(), `"abc"`)
	require.Contains(t, err.Error(), "reused")
	var target *SessionIDReusedError
	require.True(t, errors.As(error(err), &target))
}

func TestBlacklistedPartyErrorMessage(t *testing.T) {
	err := &BlacklistedPartyError{PartyIDs: []int{2}, Phase: "SignRound1"}
	require.Contains(t, err.Error(), "blacklisted")
	require.Contains(t, err.Error(), "2")
}

func TestErrorsAs(t *testing.T) {
	// CheatingPartyError
	var cheatErr error = &CheatingPartyError{PartyIDs: []int{2}, Phase: "test", Detail: "d"}
	var target *CheatingPartyError
	require.True(t, errors.As(cheatErr, &target))
	require.Equal(t, []int{2}, target.PartyIDs)

	// InvalidInputError
	var inputErr error = &InvalidInputError{Phase: "test", Detail: "d"}
	var target2 *InvalidInputError
	require.True(t, errors.As(inputErr, &target2))

	// CorruptStateError
	var corruptErr error = &CorruptStateError{Phase: "test", Detail: "d"}
	var target3 *CorruptStateError
	require.True(t, errors.As(corruptErr, &target3))

	// BlacklistedPartyError
	var blErr error = &BlacklistedPartyError{PartyIDs: []int{1}, Phase: "test"}
	var target4 *BlacklistedPartyError
	require.True(t, errors.As(blErr, &target4))

	// Cross-type should not match
	require.False(t, errors.As(cheatErr, &target2))
}

func TestBlacklistEnforcement(t *testing.T) {
	t.Parallel()
	setups := fullSetup(t)
	setups[1].Blacklist[2] = true

	// SignRound1 should reject when signer set includes blacklisted party
	_, _, err := SignRound1(setups[1], "bl-test", []int{1, 2, 3})
	require.Error(t, err)
	var blErr *BlacklistedPartyError
	require.True(t, errors.As(err, &blErr))
	require.Equal(t, []int{2}, blErr.PartyIDs)

	// Should succeed without the blacklisted party (if threshold allows)
	// For 3-of-3 this won't work for signing, but the blacklist check itself should pass
	_, _, err = SignRound1(setups[1], "bl-test-ok", []int{1, 3})
	// This may fail for other reasons (missing VOLE for 2-of-3 with t=3), but NOT for blacklist
	if err != nil {
		require.False(t, errors.As(err, &blErr), "should not be a blacklist error")
	}
}

func TestRefreshBlacklistEnforcement(t *testing.T) {
	setups := fullSetup(t)
	setups[1].Blacklist[3] = true

	err := RefreshFinalize(setups[1], nil, [16]byte{}, nil, nil)
	require.Error(t, err)
	var blErr *BlacklistedPartyError
	require.True(t, errors.As(err, &blErr))
	require.Contains(t, blErr.PartyIDs, 3)
}
