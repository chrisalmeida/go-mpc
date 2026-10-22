package dkls23

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

// This checks the narrow source policy, not compiled timing behavior or
// dependency internals. Functional curve tests cannot establish those.
func TestProductionAvoidsVariableTimeAPIs(t *testing.T) {
	t.Parallel()
	for _, directory := range []string{".", "../frost"} {
		entries, err := os.ReadDir(directory)
		require.NoError(t, err)
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			name := filepath.Join(directory, entry.Name())
			parsed, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
			require.NoError(t, err)
			for _, imported := range parsed.Imports {
				require.NotEqual(t, `"math/big"`, imported.Path.Value, "%s", name)
			}
			ast.Inspect(parsed, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if ok {
					if selected, ok := call.Fun.(*ast.SelectorExpr); ok {
						require.NotContains(t, selected.Sel.Name, "NonConst", "%s", name)
					}
				}
				return true
			})
		}
	}
}

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
	nonCanonicalX := make([]byte, 33)
	for i := range nonCanonicalX {
		nonCanonicalX[i] = 0xff
	}
	nonCanonicalX[0] = 0x02 // x = 2^256-1 is outside the base field.
	for _, encoded := range [][]byte{nil, {0}, p.EncodeUncompressed(), make([]byte, 33), nonCanonicalX} {
		_, err := compressedToPoint(encoded)
		require.Error(t, err)
	}
	decoded, err := compressedToPoint(p.Encode())
	require.NoError(t, err)
	require.Equal(t, 1, p.Equal(decoded))
}
