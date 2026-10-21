package dkls23

import (
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

func BenchmarkDKG3of3(b *testing.B) {
	allIDs := []int{1, 2, 3}
	threshold := 3
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		configs := map[int]DKGPartyConfig{}
		privs := map[int]*DKGPrivateState{}
		r1 := map[int]*DKGRound1Output{}
		for _, id := range allIDs {
			cfg := DKGPartyConfig{MyID: id, AllIDs: allIDs, Threshold: threshold}
			configs[id] = cfg
			out, priv, err := DKGRound1(cfg)
			if err != nil {
				b.Fatal(err)
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
				b.Fatal(err)
			}
			r2[id] = out
		}
		for _, id := range allIDs {
			_, _, err := DKGFinalize(configs[id], privs[id], r1, r2)
			if err != nil {
				b.Fatal(err)
			}
		}
	}
}

func BenchmarkSign3of3(b *testing.B) {
	b.StopTimer()
	setups := fullSetup(b)
	message := []byte("benchmark message")
	signers := []int{1, 2, 3}
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		sigID := fmt.Sprintf("bench-sig-%d", i)

		// Round 1.
		round1States := make(map[int]*Round1State)
		round1Msgs := make(map[int]map[int]*Round1Msg)
		for _, id := range signers {
			st, msgs, err := SignRound1(setups[id], sigID, signers)
			if err != nil {
				b.Fatal(err)
			}
			round1States[id] = st
			round1Msgs[id] = msgs
		}

		// Round 2.
		round2States := make(map[int]*Round2State)
		round2Msgs := make(map[int]map[int]*Round2Msg)
		for _, id := range signers {
			inbound := map[int]*Round1Msg{}
			for _, j := range signers {
				if j != id {
					inbound[j] = round1Msgs[j][id]
				}
			}
			st, msgs, err := SignRound2(setups[id], round1States[id], inbound)
			if err != nil {
				b.Fatal(err)
			}
			round2States[id] = st
			round2Msgs[id] = msgs
		}

		// Round 3.
		round3Frags := make(map[int]map[int]*Round3Msg)
		for _, id := range signers {
			inbound := map[int]*Round2Msg{}
			for _, j := range signers {
				if j != id {
					inbound[j] = round2Msgs[j][id]
				}
			}
			frags, err := SignRound3(setups[id], round2States[id], message, inbound)
			if err != nil {
				b.Fatal(err)
			}
			round3Frags[id] = frags
		}

		// Combine.
		combiner := signers[0]
		myFrag := round3Frags[combiner][combiner]
		var myW, myU btcec.ModNScalar
		myW.SetByteSlice(myFrag.W_i)
		myU.SetByteSlice(myFrag.U_i)
		rx := computeRxFromStates(signers, round2States)
		allRound3 := make(map[int]*Round3Msg)
		for _, j := range signers {
			if j != combiner {
				allRound3[j] = round3Frags[j][combiner]
			}
		}
		_, _, err := SignCombine(setups[combiner], &rx, &myW, &myU, allRound3, message)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBaseOTSetup(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := runBaseOT()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVOLESession(b *testing.B) {
	b.StopTimer()
	alice, bob, err := runBaseOT()
	require.NoError(b, err)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		sid := []byte(fmt.Sprintf("bench-session-%d", i))
		_, _, err := runVOLESession(alice, bob, sid)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVOLEMultiply(b *testing.B) {
	b.StopTimer()
	alice, bob, err := runVOLEPairwise()
	require.NoError(b, err)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		sid := fmt.Sprintf("bench-vole-%d", i)
		var r_i, sk_i btcec.ModNScalar
		r_i.SetInt(uint32(i + 1))
		sk_i.SetInt(uint32(i + 42))
		_, _, msg, err := VOLEAliceMultiply(alice, sid, &r_i, &sk_i)
		if err != nil {
			b.Fatal(err)
		}
		_, _, err = VOLEBobReceive(bob, sid, msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}
