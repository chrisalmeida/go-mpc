package frost

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"sync/atomic"
	"testing"

	"filippo.io/edwards25519"
	"github.com/chrisalmeida/go-mpc/session"
	"github.com/chrisalmeida/go-mpc/session/storetest"
	"github.com/stretchr/testify/require"
)

// A test-only application codec. No new private-state format is added to frost.
type storedTestNonces struct {
	Signers         []int
	Hiding, Binding []byte
	Commitment      *NonceCommitment
}

func restoreStoreSigner(in session.Input) (*SignerState, error) {
	signer, err := UnmarshalSignerState(in.KeyCheckpoint)
	if err != nil {
		return nil, err
	}
	if err := validateSignerState(signer, "store test codec"); err != nil {
		return nil, err
	}
	if signer.KeyShare.ID != in.Scope.PartyID || string(signer.KeyShare.PublicKey) != in.Scope.PublicKey || signer.Epoch != in.Epoch {
		return nil, session.ErrCorrupt
	}
	return signer, nil
}

func TestTransactionalSigningRecoversCommitmentAndConsumesRestoredNoncesOnce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	model := &storetest.Model{}
	keys := fullSetup(t)
	owners := make(map[int]session.Scope)
	versions := make(map[int]session.Version)
	signers := []int{1, 2, 3}
	commitments := make(map[int]*NonceCommitment)
	shares := make(map[int]*SignatureShare)
	verification := make(map[int][]byte)
	message := []byte("durable FROST checkpoint recovery")
	for _, id := range signers {
		owners[id] = session.Scope{Protocol: session.FROST, PublicKey: string(keys[id].PublicKey), PartyID: id}
		checkpoint, err := MarshalSignerState(NewSignerState(keys[id]))
		require.NoError(t, err)
		versions[id], err = session.Initialize(ctx, model.Open(), owners[id], 0, checkpoint)
		require.NoError(t, err)
		verification[id] = keys[id].VerificationShare
	}
	for round := 1; round <= 2; round++ {
		for _, id := range signers {
			req := session.Request{Version: versions[id], ID: session.ID{Kind: session.Signing, Epoch: 0, Value: t.Name()}, Round: round, Participants: signers}
			var computations atomic.Int32
			compute := func(in session.Input) (session.Update, error) {
				computations.Add(1)
				signer, err := restoreStoreSigner(in)
				if err != nil {
					return session.Update{}, err
				}
				var private []byte
				var public any
				nonceID := ""
				if in.Round == 1 {
					state, commitment, err := SignRound1(signer, in.Participants)
					if err != nil {
						return session.Update{}, err
					}
					private, err = json.Marshal(storedTestNonces{Signers: state.Signers, Hiding: state.HidingNonce.Bytes(), Binding: state.BindingNonce.Bytes(), Commitment: state.Commitment})
					if err != nil {
						return session.Update{}, err
					}
					public = commitment
					nonceID = string(commitment.HidingNonceCommitment) + string(commitment.BindingNonceCommitment)
				} else {
					var stored storedTestNonces
					if err := json.Unmarshal(in.SessionCheckpoint, &stored); err != nil {
						return session.Update{}, err
					}
					hiding, err := edwards25519.NewScalar().SetCanonicalBytes(stored.Hiding)
					if err != nil {
						return session.Update{}, err
					}
					binding, err := edwards25519.NewScalar().SetCanonicalBytes(stored.Binding)
					if err != nil {
						return session.Update{}, err
					}
					state := &Round1State{Signers: stored.Signers, HidingNonce: hiding, BindingNonce: binding, Commitment: stored.Commitment}
					share, err := SignRound2(signer, state, &Round2Input{Message: message, AllCommitments: commitments})
					if err != nil {
						return session.Update{}, err
					}
					public = share
				}
				output, err := json.Marshal(public)
				if err != nil {
					return session.Update{}, err
				}
				key, err := MarshalSignerState(signer)
				return session.Update{KeyCheckpoint: key, Checkpoint: private, Output: output, NonceID: nonceID}, err
			}
			var output []byte
			if round == 1 && id == 1 {
				model.FailNext(storetest.AfterCommit)
				r, err := session.Advance(ctx, model.Open(), owners[id], req, compute)
				require.ErrorIs(t, err, storetest.ErrInjected)
				require.Nil(t, r)
				output, err = session.Output(ctx, model.Open(), owners[id], req.ID, round)
				require.NoError(t, err)
			} else if round == 2 && id == 1 {
				type result struct {
					receipt *session.Receipt
					err     error
				}
				results := make(chan result, 8)
				for range 8 {
					go func() {
						r, err := session.Advance(ctx, model.Open(), owners[id], req, compute)
						results <- result{r, err}
					}()
				}
				successes := 0
				for range 8 {
					r := <-results
					if r.err == nil {
						successes++
						output = r.receipt.Output
					} else {
						require.Nil(t, r.receipt)
						require.ErrorIs(t, r.err, session.ErrStale)
					}
				}
				require.Equal(t, 1, successes)
			} else {
				r, err := session.Advance(ctx, model.Open(), owners[id], req, compute)
				require.NoError(t, err)
				output = r.Output
			}
			require.EqualValues(t, 1, computations.Load())
			key, err := session.InspectKey(ctx, model.Open(), owners[id])
			require.NoError(t, err)
			versions[id] = key.Version
			req.Version = key.Version
			_, err = session.Advance(ctx, model.Open(), owners[id], req, compute)
			require.ErrorIs(t, err, session.ErrProgress)
			require.EqualValues(t, 1, computations.Load())
			if round == 1 {
				var commitment NonceCommitment
				require.NoError(t, json.Unmarshal(output, &commitment))
				commitments[id] = &commitment
			} else {
				var share SignatureShare
				require.NoError(t, json.Unmarshal(output, &share))
				shares[id] = &share
				record, err := session.InspectSession(ctx, model.Open(), owners[id], req.ID)
				require.NoError(t, err)
				require.Empty(t, record.Checkpoint)
			}
		}
	}
	signature, err := Aggregate(commitments, shares, message, keys[1].PublicKey, verification, signers)
	require.NoError(t, err)
	require.True(t, ed25519.Verify(keys[1].PublicKey, message, signature.Bytes()))
}
