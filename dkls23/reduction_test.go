package dkls23

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func TestReduce64MatchesBigInt(t *testing.T) {
	t.Parallel()
	var zero, one, highOne, max, random [64]byte
	one[63] = 1
	highOne[31] = 1
	for i := range max {
		max[i] = 0xff
	}
	_, err := rand.Read(random[:])
	require.NoError(t, err)
	var order, twiceOrder [64]byte
	curveOrder.FillBytes(order[:])
	new(big.Int).Lsh(new(big.Int).Set(curveOrder), 1).FillBytes(twiceOrder[:])
	for _, input := range [][64]byte{zero, one, highOne, max, random, order, twiceOrder} {
		want := new(big.Int).Mod(new(big.Int).SetBytes(input[:]), curveOrder)
		got := reduce64(&input)
		encoded := got.Bytes()
		require.Equal(t, 0, want.Cmp(new(big.Int).SetBytes(encoded[:])))
	}
}

// Pin both the original PRF transcript and the exact integer reduction. A
// zero-sum test alone would also pass if both peers used the wrong hash input.
func TestFZeroMatchesReferenceReduction(t *testing.T) {
	t.Parallel()
	seed := [16]byte{1, 2, 3, 4, 5, 6, 7, 8}
	index := []byte("FZero reference transcript")
	xof := sha3.NewShake256()
	xof.Write([]byte("fzero"))
	xof.Write(seed[:])
	var ids [8]byte
	binary.BigEndian.PutUint32(ids[:4], 1)
	binary.BigEndian.PutUint32(ids[4:], 2)
	xof.Write(ids[:])
	xof.Write(index)
	var output [64]byte
	xof.Read(output[:])
	want := new(big.Int).Mod(new(big.Int).SetBytes(output[:]), curveOrder)
	positive := FZeroSample(map[int][16]byte{1: seed}, 2, index)
	negative := FZeroSample(map[int][16]byte{2: seed}, 1, index)
	encoded := positive.Bytes()
	require.Equal(t, 0, want.Cmp(new(big.Int).SetBytes(encoded[:])))
	positive.Add(&negative)
	require.True(t, positive.IsZero())
}
