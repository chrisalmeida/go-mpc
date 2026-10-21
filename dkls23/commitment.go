package dkls23

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"

	"github.com/btcsuite/btcd/btcec/v2"
	"golang.org/x/crypto/sha3"
)

// --- FCom: hash commitment scheme (paper §3.1) ---

// Commit creates a hash commitment to msg using a freshly sampled random salt.
// commitment = SHA-256(msg || salt), where salt is SaltLen random bytes.
// The caller must keep (msg, salt) secret until they call Open.
func Commit(msg []byte) (com [32]byte, salt [SaltLen]byte, err error) {
	if _, err = rand.Read(salt[:]); err != nil {
		return
	}
	h := sha256.New()
	h.Write(msg)
	h.Write(salt[:])
	copy(com[:], h.Sum(nil))
	return
}

// Open verifies a hash commitment in constant time.
// It returns an error if the commitment does not match SHA-256(msg || salt).
func Open(msg []byte, com [32]byte, salt [SaltLen]byte) error {
	h := sha256.New()
	h.Write(msg)
	h.Write(salt[:])
	expected := h.Sum(nil)
	if subtle.ConstantTimeCompare(expected, com[:]) != 1 {
		return errors.New("dkls23 Open: commitment verification failed")
	}
	return nil
}

// --- FZero: zero-sharing functionality (paper §3.1) ---

// FZeroSetupRound1 is the first round of the FZero two-party setup between Pi and Pj.
// Pi samples a 16-byte seed, commits to it with FCom, and returns the commitment.
// The seed is kept private until FZeroSetupFinalize is called.
func FZeroSetupRound1() (myCom [32]byte, mySalt [SaltLen]byte, mySeed [16]byte, err error) {
	if _, err = rand.Read(mySeed[:]); err != nil {
		return
	}
	myCom, mySalt, err = Commit(mySeed[:])
	return
}

// FZeroSetupFinalize verifies the counterparty's commitment and computes the shared seed.
// The shared seed is XOR of the two party seeds, ensuring neither party can bias the result.
// Returns error if the counterparty's commitment does not verify.
func FZeroSetupFinalize(mySeed [16]byte, theirCom [32]byte, theirSalt [SaltLen]byte, theirSeed [16]byte) ([16]byte, error) {
	if err := Open(theirSeed[:], theirCom, theirSalt); err != nil {
		return [16]byte{}, errors.New("dkls23 FZeroSetupFinalize: commitment verification failed")
	}
	var shared [16]byte
	for i := 0; i < 16; i++ {
		shared[i] = mySeed[i] ^ theirSeed[i]
	}
	return shared, nil
}

// FZeroSample samples a zero-sharing value for party myID using the shared seeds.
// For each counterparty j with a shared seed, the pair (i,j) produces a hash value:
//
//	h_{i,j} = SHAKE256("fzero" || seed_{min,max} || min(i,j) || max(i,j) || index) mod q
//
// If myID < j: subtract h_{i,j} (party with smaller ID contributes -h).
// If myID > j: add h_{i,j} (party with larger ID contributes +h).
// Since both parties compute the same h (same seed, same canonical arguments),
// the sum over all parties equals 0 mod q, realizing FZero (paper §3.1).
func FZeroSample(sharedSeeds map[int][16]byte, myID int, index []byte) btcec.ModNScalar {
	var acc btcec.ModNScalar

	for j, seed := range sharedSeeds {
		if j == myID {
			continue
		}
		// Canonical ordering: always hash with (min, max) so both parties get the same h.
		lo, hi := myID, j
		if lo > hi {
			lo, hi = hi, lo
		}

		// Domain-separated hash: "fzero" || seed || lo (4 bytes) || hi (4 bytes) || index
		xof := sha3.NewShake256()
		xof.Write([]byte(domainFZero))
		xof.Write(seed[:])
		var buf4 [4]byte
		buf4[0] = byte(lo >> 24)
		buf4[1] = byte(lo >> 16)
		buf4[2] = byte(lo >> 8)
		buf4[3] = byte(lo)
		xof.Write(buf4[:])
		buf4[0] = byte(hi >> 24)
		buf4[1] = byte(hi >> 16)
		buf4[2] = byte(hi >> 8)
		buf4[3] = byte(hi)
		xof.Write(buf4[:])
		xof.Write(index)

		var out [64]byte
		xof.Read(out[:])
		h := reduce64(&out)
		clear(out[:])

		if myID < j {
			// Party with smaller ID subtracts.
			var negH btcec.ModNScalar
			negH.NegateVal(&h)
			acc.Add(&negH)
		} else {
			// Party with larger ID adds.
			acc.Add(&h)
		}
	}
	return acc
}
