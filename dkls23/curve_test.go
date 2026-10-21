package dkls23

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

// Differential tests check the group backend independently against btcec,
// including zero, q-1, arbitrary points, complete addition and cancellation.
// They check mathematical compatibility, not the absence of side channels.
func TestCurveOperationsMatchBTCEC(t *testing.T) {
	t.Parallel()
	var zero, one, minusOne btcec.ModNScalar
	one.SetInt(1)
	minusOne.SetInt(1).Negate()
	random, err := sampleScalar()
	require.NoError(t, err)
	pointScalar, err := sampleScalar()
	require.NoError(t, err)
	point := scalarMulG(&pointScalar)
	var referencePoint btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(&pointScalar, &referencePoint)
	for _, s := range []btcec.ModNScalar{zero, one, minusOne, random} {
		converted := curveScalar(&s)
		encoded := s.Bytes()
		require.Equal(t, encoded[:], converted.Encode())
		converted.Zero()
		var base, product btcec.JacobianPoint
		btcec.ScalarBaseMultNonConst(&s, &base)
		btcec.ScalarMultNonConst(&s, &referencePoint, &product)
		for _, pair := range []struct {
			actual    *curvePoint
			reference *btcec.JacobianPoint
		}{{scalarMulG(&s), &base}, {scalarMul(&s, point), &product}} {
			pair.reference.ToAffine()
			if pair.reference.X.IsZero() && pair.reference.Y.IsZero() {
				require.True(t, pair.actual.IsIdentity())
				continue
			}
			want := btcec.NewPublicKey(&pair.reference.X, &pair.reference.Y).SerializeCompressed()
			got, err := pointToCompressed(pair.actual)
			require.NoError(t, err)
			require.Equal(t, want, got)
		}
	}
	var sum btcec.JacobianPoint
	btcec.AddNonConst(&referencePoint, &referencePoint, &sum)
	sum.ToAffine()
	require.Equal(t, btcec.NewPublicKey(&sum.X, &sum.Y).SerializeCompressed(), pointAdd(point, point).Encode())
	require.True(t, pointAdd(point, pointNeg(point)).IsIdentity())
	require.Equal(t, 1, pointAdd(newCurvePoint(), point).Equal(point))
	require.Equal(t, 1, pointAdd(point, newCurvePoint()).Equal(point))
}

func TestComputeRxRejectsCancellingNonces(t *testing.T) {
	t.Parallel()
	var one btcec.ModNScalar
	one.SetInt(1)
	p := scalarMulG(&one)
	_, err := ComputeRx(map[int][]byte{1: p.Encode(), 2: pointNeg(p).Encode()})
	var invalid *InvalidInputError
	require.ErrorAs(t, err, &invalid)
}

func TestPointDecodeRequiresCompressedSEC1(t *testing.T) {
	t.Parallel()
	var one btcec.ModNScalar
	one.SetInt(1)
	p := scalarMulG(&one)
	for _, encoded := range [][]byte{nil, {0}, p.EncodeUncompressed(), make([]byte, 33)} {
		_, err := compressedToPoint(encoded)
		require.Error(t, err)
	}
	decoded, err := compressedToPoint(p.Encode())
	require.NoError(t, err)
	require.Equal(t, 1, p.Equal(decoded))
}
