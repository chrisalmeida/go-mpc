package frost

import (
	"crypto/subtle"
	"fmt"
	"slices"

	"filippo.io/edwards25519"
)

// validateKeyShare checks configured signing material from RFC 9591 Section 5.
// Optional public verification data is checked when present. Aggregated DKG
// coefficients can contain the identity; they are local metadata, not received
// protocol elements. After refresh they describe the original DKG polynomial,
// so they cannot validate the current share. Their constant term still equals
// the unchanged group public key. Protocol element decoding stays unchanged.
// The secret-share check uses edwards25519 v1.2.0's SetCanonicalBytes and
// ScalarBaseMult: scalar.go checks reduction with a fixed subtraction chain;
// scalarmult.go documents constant-time multiplication and uses masked table
// selection. See https://github.com/FiloSottile/edwards25519/tree/v1.2.0.
func validateKeyShare(key *KeyShare, phase string) error {
	bad := func(detail string) error { return &CorruptStateError{Phase: phase, Detail: detail} }
	if key == nil {
		return bad("missing key share")
	}
	if err := validatePartyIDs(key.AllIDs, phase); err != nil {
		return bad("invalid configured participant identifiers")
	}
	if key.Threshold < 1 || key.Threshold > len(key.AllIDs) || !slices.Contains(key.AllIDs, key.ID) {
		return bad("invalid threshold or local participant")
	}
	secret, err := edwards25519.NewScalar().SetCanonicalBytes(key.SecretShare)
	if err != nil {
		return bad("invalid secret share encoding")
	}
	defer secret.Set(edwards25519.NewScalar())
	if _, err := deserializeElement(key.PublicKey); err != nil {
		return bad("invalid group public key")
	}
	if len(key.VerificationShare) != 0 {
		actual := edwards25519.NewGeneratorPoint().ScalarBaseMult(secret).Bytes()
		if subtle.ConstantTimeCompare(actual, key.VerificationShare) != 1 {
			return bad("verification share does not match the secret share")
		}
	}
	if len(key.GroupCommitments) != 0 {
		if len(key.GroupCommitments) != key.Threshold || !slices.Equal(key.GroupCommitments[0], key.PublicKey) {
			return bad("invalid aggregated DKG commitment vector")
		}
		for i, encoded := range key.GroupCommitments {
			_, err := deserializeElement(encoded)
			// A sum of valid coefficient commitments can be the identity.
			// deserializeElement checks canonical encoding before this error.
			if err != nil && err != errElementIdentity {
				return bad(fmt.Sprintf("invalid aggregated DKG commitment %d", i))
			}
		}
	}
	return nil
}

// validateSignerState checks the state wrapper without changing its epoch,
// blacklist, outstanding nonces, or refresh records. The caller holds mu or
// owns a newly decoded state.
func validateSignerState(signer *SignerState, phase string) error {
	if signer == nil {
		return &CorruptStateError{Phase: phase, Detail: "missing signer state"}
	}
	if err := validateKeyShare(signer.KeyShare, phase); err != nil {
		return err
	}
	if signer.Epoch < 0 {
		return &CorruptStateError{Phase: phase, Detail: "negative key epoch"}
	}
	for id := range signer.Blacklist {
		if id < 1 || id > maxPartyID {
			return &CorruptStateError{Phase: phase, Detail: "invalid blacklist participant identifier"}
		}
	}
	return nil
}

// validateSigningState checks membership for the configured RFC 9591 signing
// group before generating a nonce or accepting a signing request.
func validateSigningState(signer *SignerState, signers []int, phase string) error {
	if signer == nil || signer.KeyShare == nil {
		return &CorruptStateError{Phase: phase, Detail: "missing signer or key share"}
	}
	if err := validatePartyIDs(signers, phase); err != nil {
		return err
	}
	if len(signers) < signer.KeyShare.Threshold {
		return &InvalidInputError{Phase: phase, Detail: fmt.Sprintf("signer count %d below threshold %d", len(signers), signer.KeyShare.Threshold)}
	}
	if !slices.Contains(signers, signer.KeyShare.ID) {
		return &InvalidInputError{Phase: phase, Detail: "myID not in signers list"}
	}
	for _, id := range signers {
		if !slices.Contains(signer.KeyShare.AllIDs, id) {
			return &InvalidInputError{Phase: phase, Detail: "signer is not a configured participant"}
		}
	}
	return validateSignerState(signer, phase)
}

// validateRefreshCoefficients checks the private zero-constant polynomial
// supplied to the existing refresh rounds before scalar arithmetic uses it.
func validateRefreshCoefficients(coeffs []*edwards25519.Scalar, threshold int, phase string) error {
	if len(coeffs) != threshold-1 {
		return &CorruptStateError{Phase: phase, Detail: "incorrect local polynomial size"}
	}
	for _, coefficient := range coeffs {
		if coefficient == nil {
			return &CorruptStateError{Phase: phase, Detail: "missing local polynomial coefficient"}
		}
	}
	return nil
}
