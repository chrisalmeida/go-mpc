package dkls23

import (
	"crypto/subtle"
	"fmt"
	"slices"

	"github.com/btcsuite/btcd/btcec/v2"
)

// validateSetupState checks the local configuration and present setup material
// of Protocol 3.6. Missing pairwise setup is allowed until a signing set uses
// that peer; this preserves pairwise setup on demand. The caller holds mu or
// owns a newly decoded setup. Local checks cannot prove correlations with a
// peer's secret seeds or associate a Shamir share with the master public key.
func validateSetupState(setup *SignerSetup, phase string) error {
	bad := func(detail string) error { return &CorruptStateError{Phase: phase, Detail: detail} }
	if setup == nil {
		return bad("missing setup")
	}
	if err := validatePartyIDs(setup.AllIDs, phase); err != nil {
		return bad("invalid configured participant identifiers")
	}
	if setup.Threshold < 1 || setup.Threshold > len(setup.AllIDs) || !slices.Contains(setup.AllIDs, setup.MyID) {
		return bad("invalid threshold or local participant")
	}
	if setup.Epoch < 0 {
		return bad("negative key epoch")
	}
	if _, err := compressedToPoint(setup.PubKey); err != nil {
		return bad("invalid master public key")
	}
	peer := func(id int) bool { return id != setup.MyID && slices.Contains(setup.AllIDs, id) }
	for id, seeds := range setup.AliceBaseOT {
		if !peer(id) || seeds == nil || len(seeds.Seeds) != LambdaC || len(seeds.Sigma) != LambdaC {
			return bad(fmt.Sprintf("invalid base-OT receiver material for party %d", id))
		}
		for _, seed := range seeds.Seeds {
			if len(seed) != 32 {
				return bad(fmt.Sprintf("invalid base-OT receiver seed width for party %d", id))
			}
		}
	}
	for id, seeds := range setup.BobBaseOT {
		if !peer(id) || seeds == nil || len(seeds.Seeds0) != LambdaC || len(seeds.Seeds1) != LambdaC {
			return bad(fmt.Sprintf("invalid base-OT sender material for party %d", id))
		}
		for i := range seeds.Seeds0 {
			if len(seeds.Seeds0[i]) != 32 || len(seeds.Seeds1[i]) != 32 {
				return bad(fmt.Sprintf("invalid base-OT sender seed width for party %d", id))
			}
		}
	}
	for id := range setup.FZeroSeeds {
		if !peer(id) {
			return bad(fmt.Sprintf("FZero material for unconfigured party %d", id))
		}
	}
	for id := range setup.Blacklist {
		if id < 1 || id > maxPartyID {
			return bad("invalid blacklist participant identifier")
		}
	}
	return nil
}

// validateSigningSetup checks the required pairwise material and membership for
// one Protocol 3.6 signing set, without reserving a session or producing output.
// The caller holds setup.mu or owns the setup exclusively.
func validateSigningSetup(setup *SignerSetup, signers []int, phase string) error {
	if setup == nil {
		return &CorruptStateError{Phase: phase, Detail: "missing setup"}
	}
	if err := validatePartyIDs(signers, phase); err != nil {
		return err
	}
	if len(signers) < setup.Threshold {
		return &InvalidInputError{Phase: phase, Detail: fmt.Sprintf("signer count %d below threshold %d", len(signers), setup.Threshold)}
	}
	if !slices.Contains(signers, setup.MyID) {
		return &InvalidInputError{Phase: phase, Detail: "myID not in signers list"}
	}
	for _, id := range signers {
		if !slices.Contains(setup.AllIDs, id) {
			return &InvalidInputError{Phase: phase, Detail: "signer is not a configured participant"}
		}
	}
	if err := validateSetupState(setup, phase); err != nil {
		return err
	}
	for _, id := range signers {
		if id != setup.MyID {
			_, hasFZero := setup.FZeroSeeds[id]
			if setup.AliceBaseOT[id] == nil || setup.BobBaseOT[id] == nil || !hasFZero {
				return &CorruptStateError{Phase: phase, Detail: fmt.Sprintf("missing pairwise setup for party %d", id)}
			}
		}
	}
	return nil
}

// validateRound1State checks locally recomputable Protocol 3.6 state before
// releasing a later-round output. It does not authenticate the JSON document
// or establish its original key/epoch association. The caller holds setup.mu.
func validateRound1State(setup *SignerSetup, state *Round1State, phase string) error {
	bad := func(detail string) error { return &CorruptStateError{Phase: phase, Detail: detail} }
	if state == nil || state.SigID == "" {
		return bad("missing round 1 state or session identifier")
	}
	if err := validateSigningSetup(setup, state.Signers, phase); err != nil {
		return err
	}
	if _, err := compressedToPoint(state.R_iPoint); err != nil {
		return bad("invalid stored nonce point")
	}
	point, err := scalarMulGCompressed(&state.R_i)
	if err != nil {
		return bad("invalid nonce scalar")
	}
	if subtle.ConstantTimeCompare(point, state.R_iPoint) != 1 {
		return bad("nonce does not match the stored nonce point")
	}
	if err := Open(state.R_iPoint, state.Com, state.Salt); err != nil {
		return bad("nonce commitment does not match the stored opening")
	}
	seeds := make(map[int][16]byte, len(state.Signers)-1)
	for _, id := range state.Signers {
		if id != setup.MyID {
			seeds[id] = setup.FZeroSeeds[id]
		}
	}
	zeta := FZeroSample(seeds, setup.MyID, []byte(state.SigID))
	defer zeta.Zero()
	if !zeta.Equals(&state.ZetaI) {
		return bad("FZero value does not match the setup and signing request")
	}
	if len(state.VoleBobForRound2) != len(state.Signers)-1 {
		return bad("incorrect number of VOLE Bob states")
	}
	for _, id := range state.Signers {
		if id == setup.MyID {
			continue
		}
		bob := state.VoleBobForRound2[id]
		if bob == nil {
			return bad(fmt.Sprintf("missing VOLE Bob state for party %d", id))
		}
		if len(bob.Gamma) != Xi {
			return bad(fmt.Sprintf("invalid VOLE Bob vector for party %d", id))
		}
		chi := GadgetInnerProduct(bob.Beta)
		matches := chi.Equals(&bob.Chi)
		chi.Zero()
		if !matches {
			return bad(fmt.Sprintf("VOLE Bob scalar does not match its choice vector for party %d", id))
		}
	}
	return nil
}

// validateRound2State checks Protocol 3.6's rerandomized share equation and
// presence of every peer output retained for round 3. It cannot recompute
// Alice's correlations without the consumed OT-extension input transcript.
func validateRound2State(setup *SignerSetup, state *Round2State, phase string) error {
	if state == nil {
		return &CorruptStateError{Phase: phase, Detail: "missing round 2 state"}
	}
	if err := validateRound1State(setup, state.Round1State, phase); err != nil {
		return err
	}
	lambda := lagrangeCoeff(setup.MyID, state.Signers)
	defer lambda.Zero()
	var expected btcec.ModNScalar
	expected.Mul2(&setup.Share, &lambda).Add(&state.ZetaI)
	defer expected.Zero()
	if !expected.Equals(&state.SK_i) {
		return &CorruptStateError{Phase: phase, Detail: "masked share does not match the setup and signing request"}
	}
	count := len(state.Signers) - 1
	if len(state.C_u) != count || len(state.C_v) != count || len(state.Round1Commits) != count {
		return &CorruptStateError{Phase: phase, Detail: "incorrect number of retained peer outputs"}
	}
	for _, id := range state.Signers {
		if id == setup.MyID {
			continue
		}
		_, hasU := state.C_u[id]
		_, hasV := state.C_v[id]
		_, hasCommitment := state.Round1Commits[id]
		if !hasU || !hasV || !hasCommitment {
			return &CorruptStateError{Phase: phase, Detail: fmt.Sprintf("missing retained output for party %d", id)}
		}
	}
	return nil
}
