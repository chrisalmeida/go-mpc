package storetest_test

import (
	"context"
	"strings"
	"testing"

	"github.com/chrisalmeida/go-mpc/session"
	"github.com/chrisalmeida/go-mpc/session/storetest"
	"github.com/stretchr/testify/require"
)

func TestModelInjectsOneCommitFailureAndHonorsCancellation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	owner := session.Scope{Protocol: session.FROST, PublicKey: strings.Repeat("k", 32), PartyID: 1}
	model := &storetest.Model{}
	reserve := func(id string) func(session.Transaction) error {
		return func(tx session.Transaction) error { return tx.UseNonce(id) }
	}
	used := func(id string) bool {
		var result bool
		require.NoError(t, model.Open().Transact(ctx, owner, func(tx session.Transaction) error {
			var err error
			result, err = tx.NonceUsed(id)
			return err
		}))
		return result
	}

	// A failure before commit discards the writes; one after commit keeps them.
	model.FailNext(storetest.BeforeCommit)
	require.ErrorIs(t, model.Open().Transact(ctx, owner, reserve("lost")), storetest.ErrInjected)
	require.False(t, used("lost"))
	model.FailNext(storetest.AfterCommit)
	require.ErrorIs(t, model.Open().Transact(ctx, owner, reserve("kept")), storetest.ErrInjected)
	require.True(t, used("kept"))

	// Read-only transactions do not consume an injected failure; the next write does, once.
	model.FailNext(storetest.BeforeCommit)
	require.True(t, used("kept"))
	require.ErrorIs(t, model.Open().Transact(ctx, owner, reserve("later")), storetest.ErrInjected)
	require.NoError(t, model.Open().Transact(ctx, owner, reserve("later")))
	require.True(t, used("later"))

	// Cancellation before the callback skips it; cancellation during it discards writes.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	called := false
	require.ErrorIs(t, model.Open().Transact(cancelled, owner, func(session.Transaction) error {
		called = true
		return nil
	}), context.Canceled)
	require.False(t, called)
	during, cancelDuring := context.WithCancel(ctx)
	require.ErrorIs(t, model.Open().Transact(during, owner, func(tx session.Transaction) error {
		cancelDuring()
		return tx.UseNonce("cancelled")
	}), context.Canceled)
	require.False(t, used("cancelled"))
}
