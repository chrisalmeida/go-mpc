package dkls23

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func randGF128(t *testing.T) gf128 {
	t.Helper()
	var v gf128
	_, err := rand.Read(v[:])
	require.NoError(t, err)
	return v
}

// hexGF128 decodes a 16-byte hex string in the package byte order (byte i,
// bit b LSB-first is the coefficient of x^{8i+b}).
func hexGF128(t *testing.T, s string) gf128 {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	require.Len(t, b, 16)
	var v gf128
	copy(v[:], b)
	return v
}

// gf128One is the multiplicative identity x^0: byte 0, bit 0.
var gf128One = gf128{0x01}

// TestGF128KnownAnswers pins the arithmetic to vectors computed with an
// independent integer-based reference implementation of multiplication in
// GF(2)[x]/(x^128 + x^7 + x^2 + x + 1), where integer bit i is the
// coefficient of x^i and bytes are little-endian.
func TestGF128KnownAnswers(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		a, b, c string
	}{
		{"x^127 * x^127 = x^254 mod P", "00000000000000000000000000000080", "00000000000000000000000000000080", "671000000000000000000000000000c0"},
		{"pattern 1", "1032547698badcfeefcdab8967452301", "0f1e2d3c4b5a69788796a5b4c3d2e1f0", "484ba0bdd4aa055c2fb663db8460f10d"},
		{"pattern 2", "01000000000000000000000000000080", "ffffffffffffffffffffffffffffffff", "38e0ffffffffffffffffffffffffffff"},
		{"pattern 3", "3c4fcf098815f7aba6d2ae2816157e2b", "340737e0a29831318d305a88a8f64332", "3af7e9c9ccdae4630b7ad8fd73d3defa"},
	}
	for _, tc := range cases {
		a, b, want := hexGF128(t, tc.a), hexGF128(t, tc.b), hexGF128(t, tc.c)
		require.Equal(t, want, gf128Mul(a, b), tc.name)
		require.Equal(t, want, gf128Mul(b, a), tc.name+" (commuted)")
	}
}

func TestGF128MulIdentity(t *testing.T) {
	t.Parallel()
	for n := 0; n < 64; n++ {
		a := randGF128(t)
		require.Equal(t, a, gf128Mul(a, gf128One), "a*1 == a")
		require.Equal(t, a, gf128Mul(gf128One, a), "1*a == a")
	}
}

func TestGF128MulZero(t *testing.T) {
	t.Parallel()
	var zero gf128
	for n := 0; n < 64; n++ {
		a := randGF128(t)
		require.Equal(t, zero, gf128Mul(a, zero), "a*0 == 0")
		require.Equal(t, zero, gf128Mul(zero, a), "0*a == 0")
	}
	require.Equal(t, zero, gf128Mul(zero, zero))
}

func TestGF128MulCommutative(t *testing.T) {
	t.Parallel()
	for n := 0; n < 64; n++ {
		a, b := randGF128(t), randGF128(t)
		require.Equal(t, gf128Mul(a, b), gf128Mul(b, a))
	}
}

func TestGF128MulAssociative(t *testing.T) {
	t.Parallel()
	for n := 0; n < 64; n++ {
		a, b, c := randGF128(t), randGF128(t), randGF128(t)
		require.Equal(t, gf128Mul(gf128Mul(a, b), c), gf128Mul(a, gf128Mul(b, c)))
	}
}

func TestGF128MulDistributive(t *testing.T) {
	t.Parallel()
	for n := 0; n < 64; n++ {
		a, b, c := randGF128(t), randGF128(t), randGF128(t)
		lhs := gf128Mul(a, gf128Xor(b, c))
		rhs := gf128Xor(gf128Mul(a, b), gf128Mul(a, c))
		require.Equal(t, lhs, rhs, "a*(b+c) == a*b + a*c")
	}
}

// TestGF128IsAField checks a^(2^128 - 1) == 1 for random non-zero a. This
// holds for every non-zero element of a field of order 2^128 but fails for
// most elements of GF(2)[x]/(f) when f is reducible, so it guards against a
// wrong reduction polynomial as well as a broken multiply.
func TestGF128IsAField(t *testing.T) {
	t.Parallel()
	var zero gf128
	for n := 0; n < 8; n++ {
		a := randGF128(t)
		require.NotEqual(t, zero, a)
		// 2^128 - 1 is all ones, so square-and-multiply folds every square in.
		r := gf128One
		p := a
		for i := 0; i < 128; i++ {
			r = gf128Mul(r, p)
			p = gf128Mul(p, p)
		}
		require.Equal(t, gf128One, r, "a^(2^128-1) must be 1")

		// Consequently a^(2^128-2) is the inverse of a.
		inv := gf128One
		p = a
		for i := 0; i < 128; i++ {
			if i > 0 { // exponent 2^128-2 has every bit set except bit 0
				inv = gf128Mul(inv, p)
			}
			p = gf128Mul(p, p)
		}
		require.Equal(t, gf128One, gf128Mul(a, inv))
	}
}

func TestGF128Reduction(t *testing.T) {
	t.Parallel()
	// x^64 is byte 8, bit 0.
	var x64 gf128
	x64[8] = 0x01
	// x^64 * x^64 = x^128 = x^7 + x^2 + x + 1 mod the irreducible polynomial,
	// which is byte 0 = 0x87 and all other bytes zero.
	var want gf128
	want[0] = 0x87
	require.Equal(t, want, gf128Mul(x64, x64))

	// x^127 * x = x^128 as well.
	var x127, x gf128
	x127[15] = 0x80
	x[0] = 0x02
	require.Equal(t, want, gf128Mul(x127, x))

	// x^127 * x^2 = x^129 = x * (x^7 + x^2 + x + 1) = x^8 + x^3 + x^2 + x
	// = byte 0: 0x0E, byte 1: 0x01.
	var x2 gf128
	x2[0] = 0x04
	var want129 gf128
	want129[0] = 0x0E
	want129[1] = 0x01
	require.Equal(t, want129, gf128Mul(x127, x2))
}

func TestGF128MulByX(t *testing.T) {
	t.Parallel()
	// Multiplying by x must shift every bit up by one position (with carry
	// across byte boundaries) when no reduction occurs.
	var x gf128
	x[0] = 0x02
	for n := 0; n < 64; n++ {
		a := randGF128(t)
		a[15] &= 0x7F // clear x^127 so no reduction happens
		var want gf128
		var carry byte
		for i := 0; i < 16; i++ {
			want[i] = (a[i] << 1) | carry
			carry = a[i] >> 7
		}
		require.Equal(t, want, gf128Mul(a, x))
	}
}

func TestGF128Xor(t *testing.T) {
	t.Parallel()
	var zero gf128
	for n := 0; n < 16; n++ {
		a, b := randGF128(t), randGF128(t)
		s := gf128Xor(a, b)
		require.Equal(t, s, gf128Xor(b, a))
		require.Equal(t, a, gf128Xor(s, b))
		require.Equal(t, zero, gf128Xor(a, a))
		require.Equal(t, a, gf128Xor(a, zero))
	}
}

func TestGF128MulBit(t *testing.T) {
	t.Parallel()
	var zero gf128
	for n := 0; n < 16; n++ {
		v := randGF128(t)
		require.Equal(t, v, gf128MulBit(v, 1))
		require.Equal(t, zero, gf128MulBit(v, 0))
		// Only the low bit is significant.
		require.Equal(t, v, gf128MulBit(v, 0xFF))
		require.Equal(t, zero, gf128MulBit(v, 0xFE))
	}
}
