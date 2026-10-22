package dkls23

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

// curveOrder is used only by independent big.Int reference calculations.
var curveOrder = btcec.S256().N

// runBaseOT runs the one-time base OT for one directed VOLE pair and returns
// Alice's receiver seeds (she is the base-OT receiver with choice bits sigma)
// and Bob's sender seed pairs.
func runBaseOT() (*BaseOTReceiverSeeds, *BaseOTSenderSeeds, error) {
	sigmaBytes := make([]byte, (LambdaC+7)/8)
	if _, err := rand.Read(sigmaBytes); err != nil {
		return nil, nil, err
	}
	sigma := make([]bool, LambdaC)
	for k := 0; k < LambdaC; k++ {
		sigma[k] = (sigmaBytes[k/8]>>(uint(k)%8))&1 == 1
	}

	// Alice (base-OT receiver) speaks first; Bob (base-OT sender) replies and
	// derives both seed pairs; Alice finalizes to obtain K^{sigma_k}_k.
	state, msg, err := BaseOTReceiverRound1(sigma)
	if err != nil {
		return nil, nil, err
	}
	defer state.Zero()
	bobSeeds0, bobSeeds1, reply, err := BaseOTSenderRound2(msg)
	if err != nil {
		return nil, nil, err
	}
	aliceSeeds, err := BaseOTReceiverFinalize(state, reply)
	if err != nil {
		return nil, nil, err
	}
	return &BaseOTReceiverSeeds{Seeds: aliceSeeds, Sigma: sigma},
		&BaseOTSenderSeeds{Seeds0: bobSeeds0, Seeds1: bobSeeds1}, nil
}

// runDKGSetups runs the full DKG and returns a SignerSetup per party with
// empty pairwise maps.
func runDKGSetups(allIDs []int, threshold int) (map[int]*SignerSetup, error) {
	configs := map[int]DKGPartyConfig{}
	privs := map[int]*DKGPrivateState{}
	r1 := map[int]*DKGRound1Output{}
	for _, id := range allIDs {
		cfg := DKGPartyConfig{MyID: id, AllIDs: allIDs, Threshold: threshold}
		configs[id] = cfg
		out, priv, err := DKGRound1(cfg)
		if err != nil {
			return nil, err
		}
		r1[id] = out
		privs[id] = priv
	}
	r2 := map[int]*DKGRound2Output{}
	for _, id := range allIDs {
		peers := map[int]*DKGRound1Output{}
		for _, j := range allIDs {
			if j != id {
				peers[j] = r1[j]
			}
		}
		out, err := DKGRound2(configs[id], privs[id], peers)
		if err != nil {
			return nil, err
		}
		r2[id] = out
	}

	setups := map[int]*SignerSetup{}
	for _, id := range allIDs {
		share, pk, err := DKGFinalize(configs[id], privs[id], r1, r2)
		if err != nil {
			return nil, err
		}
		privs[id].Zero()
		setups[id] = &SignerSetup{
			MyID: id, AllIDs: allIDs, Share: share, PubKey: pk,
			Threshold:   threshold,
			AliceBaseOT: make(map[int]*BaseOTReceiverSeeds),
			BobBaseOT:   make(map[int]*BaseOTSenderSeeds),
			FZeroSeeds:  make(map[int][16]byte),
			Blacklist:   make(map[int]bool),
		}
	}
	return setups, nil
}

// buildSetups constructs a complete SignerSetup for each party: DKG + pairwise
// base OT (both directions) + FZero, with pairwise work parallelised across goroutines.
func buildSetups(allIDs []int, threshold int) (map[int]*SignerSetup, error) {
	setups, err := runDKGSetups(allIDs, threshold)
	if err != nil {
		return nil, err
	}

	type pair struct{ i, j int }
	var pairs []pair
	for pi := 0; pi < len(allIDs); pi++ {
		for pj := pi + 1; pj < len(allIDs); pj++ {
			pairs = append(pairs, pair{allIDs[pi], allIDs[pj]})
		}
	}

	type pairResult struct {
		aliceIJ, aliceJI *BaseOTReceiverSeeds
		bobIJ, bobJI     *BaseOTSenderSeeds
		fzeroIJ, fzeroJI [16]byte
		err              error
	}

	results := make([]pairResult, len(pairs))
	var wg sync.WaitGroup
	for idx := range pairs {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			r := &results[idx]

			// Direction i→j: i is Alice (base-OT receiver), j is Bob (base-OT sender).
			r.aliceIJ, r.bobIJ, r.err = runBaseOT()
			if r.err != nil {
				return
			}
			// Direction j→i.
			r.aliceJI, r.bobJI, r.err = runBaseOT()
			if r.err != nil {
				return
			}

			com1, salt1, seed1, err := FZeroSetupRound1()
			if err != nil {
				r.err = err
				return
			}
			com2, salt2, seed2, err := FZeroSetupRound1()
			if err != nil {
				r.err = err
				return
			}
			r.fzeroIJ, err = FZeroSetupFinalize(seed1, com2, salt2, seed2)
			if err != nil {
				r.err = err
				return
			}
			r.fzeroJI, err = FZeroSetupFinalize(seed2, com1, salt1, seed1)
			if err != nil {
				r.err = err
				return
			}
		}(idx)
	}
	wg.Wait()

	for idx, p := range pairs {
		r := results[idx]
		if r.err != nil {
			return nil, r.err
		}
		setups[p.i].AliceBaseOT[p.j] = r.aliceIJ
		setups[p.j].BobBaseOT[p.i] = r.bobIJ
		setups[p.j].AliceBaseOT[p.i] = r.aliceJI
		setups[p.i].BobBaseOT[p.j] = r.bobJI
		setups[p.i].FZeroSeeds[p.j] = r.fzeroIJ
		setups[p.j].FZeroSeeds[p.i] = r.fzeroJI
	}

	return setups, nil
}

// ---- Cached 3-of-3 setup ----

var (
	cached3of3Once sync.Once
	cached3of3JSON map[int][]byte
	cached3of3Err  error
)

// fullSetup returns a 3-of-3 SignerSetup per party. The expensive crypto setup
// runs once and is cached; each call returns an independent deep copy.
func fullSetup(t testing.TB) map[int]*SignerSetup {
	t.Helper()
	cached3of3Once.Do(func() {
		setups, err := buildSetups([]int{1, 2, 3}, 3)
		if err != nil {
			cached3of3Err = err
			return
		}
		cached3of3JSON = make(map[int][]byte)
		for id, s := range setups {
			b, err := json.Marshal(s)
			if err != nil {
				cached3of3Err = err
				return
			}
			cached3of3JSON[id] = b
		}
	})
	require.NoError(t, cached3of3Err)
	result := make(map[int]*SignerSetup)
	for id, b := range cached3of3JSON {
		var s SignerSetup
		err := json.Unmarshal(b, &s)
		require.NoError(t, err)
		result[id] = &s
	}
	return result
}

// fullSign runs a 3-of-3 signing session and returns all intermediate state.
func fullSign(t testing.TB, setups map[int]*SignerSetup, msg []byte) (
	r1States map[int]*Round1State,
	r1Msgs map[int]map[int]*Round1Msg,
	r2States map[int]*Round2State,
	r2Msgs map[int]map[int]*Round2Msg,
	r3Frags map[int]map[int]*Round3Msg,
) {
	t.Helper()
	signers := []int{1, 2, 3}
	sigID := "test-encoding-sig"

	r1States = make(map[int]*Round1State)
	r1Msgs = make(map[int]map[int]*Round1Msg)
	for _, id := range signers {
		st, msgs, err := SignRound1(setups[id], sigID, signers)
		require.NoError(t, err)
		r1States[id] = st
		r1Msgs[id] = msgs
	}

	r2States = make(map[int]*Round2State)
	r2Msgs = make(map[int]map[int]*Round2Msg)
	for _, id := range signers {
		inbound := map[int]*Round1Msg{}
		for _, j := range signers {
			if j != id {
				inbound[j] = r1Msgs[j][id]
			}
		}
		st, msgs, err := SignRound2(setups[id], r1States[id], inbound)
		require.NoError(t, err)
		r2States[id] = st
		r2Msgs[id] = msgs
	}

	r3Frags = make(map[int]map[int]*Round3Msg)
	for _, id := range signers {
		inbound := map[int]*Round2Msg{}
		for _, j := range signers {
			if j != id {
				inbound[j] = r2Msgs[j][id]
			}
		}
		frags, err := SignRound3(setups[id], r2States[id], msg, inbound)
		require.NoError(t, err)
		r3Frags[id] = frags
	}
	return
}

// computeRxFromStates computes rx = (Σ R_j).x mod q from Round2State R_iPoint values.
func computeRxFromStates(signers []int, states map[int]*Round2State) btcec.ModNScalar {
	var R btcec.JacobianPoint
	for _, id := range signers {
		pub, err := btcec.ParsePubKey(states[id].R_iPoint)
		if err != nil {
			panic(err)
		}
		var pt btcec.JacobianPoint
		pub.AsJacobian(&pt)
		btcec.AddNonConst(&R, &pt, &R)
	}
	R.ToAffine()
	rxBytes := make([]byte, 32)
	R.X.PutBytesUnchecked(rxBytes)
	var rx btcec.ModNScalar
	rx.SetByteSlice(rxBytes)
	return rx
}

// roundTrip marshals v to JSON, unmarshals into a new value of the same type,
// then marshals again and asserts the two JSON outputs are byte-equal.
func roundTrip[T any](t *testing.T, name string, v *T) *T {
	t.Helper()
	b1, err := json.Marshal(v)
	require.NoError(t, err, "%s: first marshal", name)
	require.NotEmpty(t, b1)

	var out T
	err = json.Unmarshal(b1, &out)
	require.NoError(t, err, "%s: unmarshal", name)

	b2, err := json.Marshal(&out)
	require.NoError(t, err, "%s: second marshal", name)
	require.JSONEq(t, string(b1), string(b2), "%s: round-trip JSON mismatch", name)
	return &out
}

// failingEncryptor always returns errors, used to test error paths.
type failingEncryptor struct{}

func (f *failingEncryptor) Encrypt([]byte) ([]byte, error) {
	return nil, errors.New("encrypt failed")
}
func (f *failingEncryptor) Decrypt([]byte) ([]byte, error) {
	return nil, errors.New("decrypt failed")
}

// runVOLEPairwise is a helper for tests: runs the one-time base OT and then
// ONE session's OT-extension batch + VOLE sampling between Alice and Bob.
// Returns (aliceState, bobState) ready for VOLEAliceMultiply / VOLEBobReceive.
func runVOLEPairwise() (*VOLEAliceState, *VOLEBobState, error) {
	alice, bob, err := runBaseOT()
	if err != nil {
		return nil, nil, err
	}
	return runVOLESession(alice, bob, []byte("test-vole-session"))
}

// runVOLESession runs one OT-extension batch + VOLE sampling for the given
// session id over existing base-OT seeds.
func runVOLESession(alice *BaseOTReceiverSeeds, bob *BaseOTSenderSeeds, sid []byte) (*VOLEAliceState, *VOLEBobState, error) {
	beta, err := sampleBeta()
	if err != nil {
		return nil, nil, err
	}
	oteMsg, gamma, err := OTExtReceive(bob.Seeds0, bob.Seeds1, beta, sid)
	if err != nil {
		return nil, nil, err
	}
	alpha0, alpha1, err := OTExtSend(alice.Seeds, alice.Sigma, sid, oteMsg)
	if err != nil {
		return nil, nil, err
	}
	aliceState, err := VOLEAliceSetup(alpha0, alpha1)
	if err != nil {
		return nil, nil, err
	}
	bobState, err := VOLEBobSample(gamma, beta)
	if err != nil {
		return nil, nil, err
	}
	return aliceState, bobState, nil
}
