package dkls23

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/btcsuite/btcd/btcec/v2"
)

// SetupWireVersion is the version of the SignerSetup JSON wire format. It is
// embedded in every serialized SignerSetup and checked on deserialization so
// that stored key material from an incompatible format is rejected rather
// than silently misinterpreted.
const SetupWireVersion = 1

// --- Encoding helpers ---

// scalarToHex serializes a ModNScalar to 64-char hex (32 bytes big-endian).
func scalarToHex(s *btcec.ModNScalar) string {
	b := s.Bytes()
	return hex.EncodeToString(b[:])
}

// hexToScalar parses a 64-char hex string into a ModNScalar.
func hexToScalar(s string) (btcec.ModNScalar, error) {
	var out btcec.ModNScalar
	if s == "" {
		return out, nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("hexToScalar: %w", err)
	}
	out.SetByteSlice(b)
	return out, nil
}

// scalarMapToHex serializes map[int]ModNScalar to map[string]string for JSON.
func scalarMapToHex(m map[int]btcec.ModNScalar) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[strconv.Itoa(k)] = scalarToHex(&v)
	}
	return out
}

// hexToScalarMap deserializes map[string]string to map[int]ModNScalar from JSON.
func hexToScalarMap(m map[string]string) (map[int]btcec.ModNScalar, error) {
	out := make(map[int]btcec.ModNScalar, len(m))
	for k, v := range m {
		id, err := strconv.Atoi(k)
		if err != nil {
			return nil, err
		}
		val, err := hexToScalar(v)
		if err != nil {
			return nil, err
		}
		out[id] = val
	}
	return out, nil
}

func bytesToHex(b []byte) string { return hex.EncodeToString(b) }

func hexToBytes(s string) ([]byte, error) { return hex.DecodeString(s) }

func hexToFixed32(s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, err
	}
	if len(b) != 32 {
		return out, fmt.Errorf("expected 32 bytes, got %d", len(b))
	}
	copy(out[:], b)
	return out, nil
}

func hexToFixed16(s string) ([16]byte, error) {
	var out [16]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, err
	}
	if len(b) != 16 {
		return out, fmt.Errorf("expected 16 bytes, got %d", len(b))
	}
	copy(out[:], b)
	return out, nil
}

// intMapKeys converts map[int]V to map[string]V for JSON.
func intMapKeys[V any](m map[int]V) map[string]V {
	if m == nil {
		return nil
	}
	out := make(map[string]V, len(m))
	for k, v := range m {
		out[strconv.Itoa(k)] = v
	}
	return out
}

// stringMapKeys converts map[string]V to map[int]V from JSON.
func stringMapKeys[V any](m map[string]V) (map[int]V, error) {
	if m == nil {
		return nil, nil
	}
	out := make(map[int]V, len(m))
	for k, v := range m {
		id, err := strconv.Atoi(k)
		if err != nil {
			return nil, fmt.Errorf("invalid party ID %q: %w", k, err)
		}
		out[id] = v
	}
	return out, nil
}

// map[int][32]byte ↔ map[string]string
func intMap32ToJSON(m map[int][32]byte) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[strconv.Itoa(k)] = hex.EncodeToString(v[:])
	}
	return out
}

func jsonToIntMap32(m map[string]string) (map[int][32]byte, error) {
	out := make(map[int][32]byte, len(m))
	for k, v := range m {
		id, err := strconv.Atoi(k)
		if err != nil {
			return nil, err
		}
		b, err := hexToFixed32(v)
		if err != nil {
			return nil, err
		}
		out[id] = b
	}
	return out, nil
}

// map[int][16]byte ↔ map[string]string
func intMap16ToJSON(m map[int][16]byte) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[strconv.Itoa(k)] = hex.EncodeToString(v[:])
	}
	return out
}

func jsonToIntMap16(m map[string]string) (map[int][16]byte, error) {
	out := make(map[int][16]byte, len(m))
	for k, v := range m {
		id, err := strconv.Atoi(k)
		if err != nil {
			return nil, err
		}
		b, err := hexToFixed16(v)
		if err != nil {
			return nil, err
		}
		out[id] = b
	}
	return out, nil
}

// map[int][]byte ↔ map[string]string (hex encoded values)
func intMapBytesToJSON(m map[int][]byte) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[strconv.Itoa(k)] = hex.EncodeToString(v)
	}
	return out
}

func jsonToIntMapBytes(m map[string]string) (map[int][]byte, error) {
	out := make(map[int][]byte, len(m))
	for k, v := range m {
		id, err := strconv.Atoi(k)
		if err != nil {
			return nil, err
		}
		b, err := hex.DecodeString(v)
		if err != nil {
			return nil, err
		}
		out[id] = b
	}
	return out, nil
}

// --- VOLE array encoding ---
// The VOLE arrays are large (up to 53KB) so we flatten to binary + base64.

func encodeVOLESlice(data [][Ell + Rho][32]byte) string {
	n := len(data)
	buf := make([]byte, n*(Ell+Rho)*32)
	for j := range data {
		for i := 0; i < Ell+Rho; i++ {
			copy(buf[(j*(Ell+Rho)+i)*32:], data[j][i][:])
		}
	}
	return base64.StdEncoding.EncodeToString(buf)
}

func decodeVOLESlice(s string) ([][Ell + Rho][32]byte, error) {
	buf, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	entrySize := (Ell + Rho) * 32
	if len(buf)%entrySize != 0 {
		return nil, fmt.Errorf("VOLE slice data size %d not divisible by %d", len(buf), entrySize)
	}
	n := len(buf) / entrySize
	out := make([][Ell + Rho][32]byte, n)
	for j := 0; j < n; j++ {
		for i := 0; i < Ell+Rho; i++ {
			copy(out[j][i][:], buf[(j*(Ell+Rho)+i)*32:])
		}
	}
	return out, nil
}

func encodeVOLEFixed(data [Xi][Ell + Rho][32]byte) string {
	buf := make([]byte, Xi*(Ell+Rho)*32)
	for j := 0; j < Xi; j++ {
		for i := 0; i < Ell+Rho; i++ {
			copy(buf[(j*(Ell+Rho)+i)*32:], data[j][i][:])
		}
	}
	return base64.StdEncoding.EncodeToString(buf)
}

func decodeVOLEFixed(s string) ([Xi][Ell + Rho][32]byte, error) {
	var out [Xi][Ell + Rho][32]byte
	buf, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return out, err
	}
	expected := Xi * (Ell + Rho) * 32
	if len(buf) != expected {
		return out, fmt.Errorf("VOLE fixed data size %d, expected %d", len(buf), expected)
	}
	for j := 0; j < Xi; j++ {
		for i := 0; i < Ell+Rho; i++ {
			copy(out[j][i][:], buf[(j*(Ell+Rho)+i)*32:])
		}
	}
	return out, nil
}

func encodeRhoFixed(data [Rho][32]byte) string {
	buf := make([]byte, Rho*32)
	for k := 0; k < Rho; k++ {
		copy(buf[k*32:], data[k][:])
	}
	return hex.EncodeToString(buf)
}

func decodeRhoFixed(s string) ([Rho][32]byte, error) {
	var out [Rho][32]byte
	buf, err := hex.DecodeString(s)
	if err != nil {
		return out, err
	}
	if len(buf) != Rho*32 {
		return out, fmt.Errorf("rho data size %d, expected %d", len(buf), Rho*32)
	}
	for k := 0; k < Rho; k++ {
		copy(out[k][:], buf[k*32:])
	}
	return out, nil
}

func encodeBoolArray(data [Xi]bool) string {
	buf := make([]byte, (Xi+7)/8)
	for j := 0; j < Xi; j++ {
		if data[j] {
			buf[j/8] |= 1 << (uint(j) % 8)
		}
	}
	return base64.StdEncoding.EncodeToString(buf)
}

func decodeBoolArray(s string) ([Xi]bool, error) {
	var out [Xi]bool
	buf, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return out, err
	}
	if len(buf) != (Xi+7)/8 {
		return out, fmt.Errorf("bool array size %d, expected %d", len(buf), (Xi+7)/8)
	}
	for j := 0; j < Xi; j++ {
		out[j] = (buf[j/8]>>(uint(j)%8))&1 == 1
	}
	return out, nil
}

// encodeBoolSlice packs a []bool (LSB-first per byte) and base64-encodes it.
func encodeBoolSlice(data []bool) string {
	buf := make([]byte, (len(data)+7)/8)
	for j, b := range data {
		if b {
			buf[j/8] |= 1 << (uint(j) % 8)
		}
	}
	return base64.StdEncoding.EncodeToString(buf)
}

// decodeBoolSlice decodes exactly n bits packed by encodeBoolSlice.
func decodeBoolSlice(s string, n int) ([]bool, error) {
	buf, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(buf) != (n+7)/8 {
		return nil, fmt.Errorf("bool slice size %d, expected %d", len(buf), (n+7)/8)
	}
	out := make([]bool, n)
	for j := 0; j < n; j++ {
		out[j] = (buf[j/8]>>(uint(j)%8))&1 == 1
	}
	return out, nil
}

// [][]byte ↔ []string (hex)
func encodeBytesSlice(data [][]byte) []string {
	out := make([]string, len(data))
	for i, b := range data {
		out[i] = hex.EncodeToString(b)
	}
	return out
}

func decodeBytesSlice(data []string) ([][]byte, error) {
	out := make([][]byte, len(data))
	for i, s := range data {
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, err
		}
		out[i] = b
	}
	return out, nil
}

// decodeSeedSlice decodes exactly LambdaC 32-byte seeds.
func decodeSeedSlice(data []string) ([][]byte, error) {
	if len(data) != LambdaC {
		return nil, fmt.Errorf("expected %d seeds, got %d", LambdaC, len(data))
	}
	out, err := decodeBytesSlice(data)
	if err != nil {
		return nil, err
	}
	for i, s := range out {
		if len(s) != 32 {
			return nil, fmt.Errorf("seed %d: expected 32 bytes, got %d", i, len(s))
		}
	}
	return out, nil
}

// =====================================================================
// DKGRound1Output
// =====================================================================

type dkgRound1OutputJSON struct {
	FeldmanCommitment   string            `json:"feldman_commitment"`
	PairwiseCommitments map[string]string `json:"pairwise_commitments"`
}

func (o *DKGRound1Output) MarshalJSON() ([]byte, error) {
	return json.Marshal(dkgRound1OutputJSON{
		FeldmanCommitment:   hex.EncodeToString(o.FeldmanCommitment[:]),
		PairwiseCommitments: intMap32ToJSON(o.PairwiseCommitments),
	})
}

func (o *DKGRound1Output) UnmarshalJSON(data []byte) error {
	next := *o
	var j dkgRound1OutputJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	var err error
	next.FeldmanCommitment, err = hexToFixed32(j.FeldmanCommitment)
	if err != nil {
		return err
	}
	next.PairwiseCommitments, err = jsonToIntMap32(j.PairwiseCommitments)
	if err != nil {
		return err
	}
	*o = next
	return nil
}

// =====================================================================
// DKGRound2Output
// =====================================================================

type dkgRound2OutputJSON struct {
	FeldmanCommitments []string          `json:"feldman_commitments"`
	FeldmanSalt        string            `json:"feldman_salt"`
	SecretShares       map[string]string `json:"secret_shares"`
	PairwiseSalts      map[string]string `json:"pairwise_salts"`
}

func (o *DKGRound2Output) MarshalJSON() ([]byte, error) {
	return json.Marshal(dkgRound2OutputJSON{
		FeldmanCommitments: encodeBytesSlice(o.FeldmanCommitments),
		FeldmanSalt:        hex.EncodeToString(o.FeldmanSalt[:]),
		SecretShares:       intMapBytesToJSON(o.SecretShares),
		PairwiseSalts:      intMap32ToJSON(o.PairwiseSalts),
	})
}

func (o *DKGRound2Output) UnmarshalJSON(data []byte) error {
	next := *o
	var j dkgRound2OutputJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	var err error
	next.FeldmanCommitments, err = decodeBytesSlice(j.FeldmanCommitments)
	if err != nil {
		return err
	}
	next.FeldmanSalt, err = hexToFixed32(j.FeldmanSalt)
	if err != nil {
		return err
	}
	next.SecretShares, err = jsonToIntMapBytes(j.SecretShares)
	if err != nil {
		return err
	}
	next.PairwiseSalts, err = jsonToIntMap32(j.PairwiseSalts)
	if err != nil {
		return err
	}
	*o = next
	return nil
}

// =====================================================================
// BaseOTSenderSeeds / BaseOTReceiverSeeds
// =====================================================================

type baseOTSenderSeedsJSON struct {
	Seeds0 []string `json:"seeds0"`
	Seeds1 []string `json:"seeds1"`
}

func (s *BaseOTSenderSeeds) MarshalJSON() ([]byte, error) {
	return json.Marshal(baseOTSenderSeedsJSON{
		Seeds0: encodeBytesSlice(s.Seeds0),
		Seeds1: encodeBytesSlice(s.Seeds1),
	})
}

func (s *BaseOTSenderSeeds) UnmarshalJSON(data []byte) error {
	next := *s
	var j baseOTSenderSeedsJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	var err error
	next.Seeds0, err = decodeSeedSlice(j.Seeds0)
	if err != nil {
		return err
	}
	next.Seeds1, err = decodeSeedSlice(j.Seeds1)
	if err != nil {
		return err
	}
	*s = next
	return nil
}

type baseOTReceiverSeedsJSON struct {
	Seeds []string `json:"seeds"`
	Sigma string   `json:"sigma"`
}

func (s *BaseOTReceiverSeeds) MarshalJSON() ([]byte, error) {
	return json.Marshal(baseOTReceiverSeedsJSON{
		Seeds: encodeBytesSlice(s.Seeds),
		Sigma: encodeBoolSlice(s.Sigma),
	})
}

func (s *BaseOTReceiverSeeds) UnmarshalJSON(data []byte) error {
	next := *s
	var j baseOTReceiverSeedsJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	var err error
	next.Seeds, err = decodeSeedSlice(j.Seeds)
	if err != nil {
		return err
	}
	next.Sigma, err = decodeBoolSlice(j.Sigma, LambdaC)
	if err != nil {
		return err
	}
	*s = next
	return nil
}

// =====================================================================
// VOLEBobState
// =====================================================================

type voleBobStateJSON struct {
	Beta  string `json:"beta"`
	Chi   string `json:"chi"`
	Gamma string `json:"gamma"`
}

func (s *VOLEBobState) MarshalJSON() ([]byte, error) {
	return json.Marshal(voleBobStateJSON{
		Beta:  encodeBoolArray(s.Beta),
		Chi:   scalarToHex(&s.Chi),
		Gamma: encodeVOLESlice(s.Gamma),
	})
}

func (s *VOLEBobState) UnmarshalJSON(data []byte) error {
	next := *s
	var j voleBobStateJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	var err error
	next.Beta, err = decodeBoolArray(j.Beta)
	if err != nil {
		return err
	}
	next.Chi, err = hexToScalar(j.Chi)
	if err != nil {
		return err
	}
	next.Gamma, err = decodeVOLESlice(j.Gamma)
	if err != nil {
		return err
	}
	*s = next
	return nil
}

// =====================================================================
// VOLEAliceState
// =====================================================================

type voleAliceStateJSON struct {
	Alpha0 string `json:"alpha0"`
	Alpha1 string `json:"alpha1"`
	CU     string `json:"c_u"`
	CV     string `json:"c_v"`
}

func (s *VOLEAliceState) MarshalJSON() ([]byte, error) {
	return json.Marshal(voleAliceStateJSON{
		Alpha0: encodeVOLESlice(s.Alpha0),
		Alpha1: encodeVOLESlice(s.Alpha1),
		CU:     scalarToHex(&s.C_u),
		CV:     scalarToHex(&s.C_v),
	})
}

func (s *VOLEAliceState) UnmarshalJSON(data []byte) error {
	next := *s
	var j voleAliceStateJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	var err error
	next.Alpha0, err = decodeVOLESlice(j.Alpha0)
	if err != nil {
		return err
	}
	next.Alpha1, err = decodeVOLESlice(j.Alpha1)
	if err != nil {
		return err
	}
	next.C_u, err = hexToScalar(j.CU)
	if err != nil {
		return err
	}
	next.C_v, err = hexToScalar(j.CV)
	if err != nil {
		return err
	}
	*s = next
	return nil
}

// =====================================================================
// VOLEMultiplyMsg
// =====================================================================

type voleMultiplyMsgJSON struct {
	SID    string `json:"sid"`
	ATilde string `json:"a_tilde"`
	Eta    string `json:"eta"`
	Mu     string `json:"mu"`
}

func (m *VOLEMultiplyMsg) MarshalJSON() ([]byte, error) {
	return json.Marshal(voleMultiplyMsgJSON{
		SID:    m.SID,
		ATilde: encodeVOLEFixed(m.ATilde),
		Eta:    encodeRhoFixed(m.Eta),
		Mu:     hex.EncodeToString(m.Mu[:]),
	})
}

func (m *VOLEMultiplyMsg) UnmarshalJSON(data []byte) error {
	next := *m
	var j voleMultiplyMsgJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	next.SID = j.SID
	var err error
	next.ATilde, err = decodeVOLEFixed(j.ATilde)
	if err != nil {
		return err
	}
	next.Eta, err = decodeRhoFixed(j.Eta)
	if err != nil {
		return err
	}
	next.Mu, err = hexToFixed32(j.Mu)
	if err != nil {
		return err
	}
	*m = next
	return nil
}

// =====================================================================
// Round1Msg
// =====================================================================

type round1MsgJSON struct {
	Commitment string            `json:"commitment"`
	OTExt      *OTExtReceiverMsg `json:"ot_ext"`
}

func (m *Round1Msg) MarshalJSON() ([]byte, error) {
	return json.Marshal(round1MsgJSON{
		Commitment: hex.EncodeToString(m.Commitment[:]),
		OTExt:      m.OTExt,
	})
}

func (m *Round1Msg) UnmarshalJSON(data []byte) error {
	next := *m
	var j round1MsgJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	var err error
	next.Commitment, err = hexToFixed32(j.Commitment)
	if err != nil {
		return err
	}
	next.OTExt = j.OTExt
	*m = next
	return nil
}

// =====================================================================
// Round1State
// =====================================================================

type round1StateJSON struct {
	SigID            string                   `json:"sig_id"`
	Signers          []int                    `json:"signers"`
	RI               string                   `json:"r_i"`
	PhiI             string                   `json:"phi_i"`
	RIPoint          string                   `json:"r_i_point"`
	Com              string                   `json:"com"`
	Salt             string                   `json:"salt"`
	ZetaI            string                   `json:"zeta_i"`
	VoleBobForRound2 map[string]*VOLEBobState `json:"vole_bob_for_round2"`
}

func (s *Round1State) MarshalJSON() ([]byte, error) {
	return json.Marshal(round1StateJSON{
		SigID:            s.SigID,
		Signers:          s.Signers,
		RI:               scalarToHex(&s.R_i),
		PhiI:             scalarToHex(&s.Phi_i),
		RIPoint:          hex.EncodeToString(s.R_iPoint),
		Com:              hex.EncodeToString(s.Com[:]),
		Salt:             hex.EncodeToString(s.Salt[:]),
		ZetaI:            scalarToHex(&s.ZetaI),
		VoleBobForRound2: intMapKeys(s.VoleBobForRound2),
	})
}

func (s *Round1State) UnmarshalJSON(data []byte) error {
	var j round1StateJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	next := Round1State{SigID: j.SigID, Signers: j.Signers}
	var err error
	next.R_i, err = hexToScalar(j.RI)
	if err != nil {
		return err
	}
	next.Phi_i, err = hexToScalar(j.PhiI)
	if err != nil {
		return err
	}
	next.R_iPoint, err = hex.DecodeString(j.RIPoint)
	if err != nil {
		return err
	}
	next.Com, err = hexToFixed32(j.Com)
	if err != nil {
		return err
	}
	next.Salt, err = hexToFixed32(j.Salt)
	if err != nil {
		return err
	}
	next.ZetaI, err = hexToScalar(j.ZetaI)
	if err != nil {
		return err
	}
	next.VoleBobForRound2, err = stringMapKeys(j.VoleBobForRound2)
	if err != nil {
		return err
	}
	// Publish only a completely decoded replacement. A rejected load must not
	// alter active private material or its lifetime metadata.
	*s = next
	return nil
}

// =====================================================================
// Round2State
// =====================================================================

type round2StateJSON struct {
	Round1State   *Round1State      `json:"round1_state"`
	SKI           string            `json:"sk_i"`
	CU            map[string]string `json:"c_u"`
	CV            map[string]string `json:"c_v"`
	Round1Commits map[string]string `json:"round1_commits"`
}

func (s *Round2State) MarshalJSON() ([]byte, error) {
	return json.Marshal(round2StateJSON{
		Round1State:   s.Round1State,
		SKI:           scalarToHex(&s.SK_i),
		CU:            scalarMapToHex(s.C_u),
		CV:            scalarMapToHex(s.C_v),
		Round1Commits: intMap32ToJSON(s.Round1Commits),
	})
}

func (s *Round2State) UnmarshalJSON(data []byte) error {
	var j round2StateJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	next := Round2State{Round1State: j.Round1State}
	var err error
	next.SK_i, err = hexToScalar(j.SKI)
	if err != nil {
		return err
	}
	next.C_u, err = hexToScalarMap(j.CU)
	if err != nil {
		return err
	}
	next.C_v, err = hexToScalarMap(j.CV)
	if err != nil {
		return err
	}
	next.Round1Commits, err = jsonToIntMap32(j.Round1Commits)
	if err != nil {
		return err
	}
	*s = next
	return nil
}

// =====================================================================
// Round2Msg
// =====================================================================

type round2MsgJSON struct {
	Decommitment string           `json:"decommitment"`
	Salt         string           `json:"salt"`
	VoleMsg      *VOLEMultiplyMsg `json:"vole_msg"`
	GammaU       string           `json:"gamma_u"`
	GammaV       string           `json:"gamma_v"`
	Psi          string           `json:"psi"`
	PKi          string           `json:"pki"`
}

func (m *Round2Msg) MarshalJSON() ([]byte, error) {
	return json.Marshal(round2MsgJSON{
		Decommitment: hex.EncodeToString(m.Decommitment),
		Salt:         hex.EncodeToString(m.Salt[:]),
		VoleMsg:      m.VoleMsg,
		GammaU:       hex.EncodeToString(m.GammaU),
		GammaV:       hex.EncodeToString(m.GammaV),
		Psi:          hex.EncodeToString(m.Psi),
		PKi:          hex.EncodeToString(m.PKi),
	})
}

func (m *Round2Msg) UnmarshalJSON(data []byte) error {
	next := *m
	var j round2MsgJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	var err error
	next.Decommitment, err = hex.DecodeString(j.Decommitment)
	if err != nil {
		return err
	}
	next.Salt, err = hexToFixed32(j.Salt)
	if err != nil {
		return err
	}
	next.VoleMsg = j.VoleMsg
	next.GammaU, err = hex.DecodeString(j.GammaU)
	if err != nil {
		return err
	}
	next.GammaV, err = hex.DecodeString(j.GammaV)
	if err != nil {
		return err
	}
	next.Psi, err = hex.DecodeString(j.Psi)
	if err != nil {
		return err
	}
	next.PKi, err = hex.DecodeString(j.PKi)
	if err != nil {
		return err
	}
	*m = next
	return nil
}

// =====================================================================
// Round3Msg — []byte fields serialize natively as base64, but we use
// hex for consistency with the rest of the protocol messages.
// =====================================================================

type round3MsgJSON struct {
	WI string `json:"w_i"`
	UI string `json:"u_i"`
}

func (m *Round3Msg) MarshalJSON() ([]byte, error) {
	return json.Marshal(round3MsgJSON{
		WI: hex.EncodeToString(m.W_i),
		UI: hex.EncodeToString(m.U_i),
	})
}

func (m *Round3Msg) UnmarshalJSON(data []byte) error {
	next := *m
	var j round3MsgJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	var err error
	next.W_i, err = hex.DecodeString(j.WI)
	if err != nil {
		return err
	}
	next.U_i, err = hex.DecodeString(j.UI)
	if err != nil {
		return err
	}
	*m = next
	return nil
}

// =====================================================================
// RefreshRound1Output
// =====================================================================

type refreshRound1OutputJSON struct {
	FeldmanCommitments  []string          `json:"feldman_commitments"`
	PairwiseCommitments map[string]string `json:"pairwise_commitments"`
	PairwiseSalts       map[string]string `json:"pairwise_salts"`
	SeedCommitment      string            `json:"seed_commitment"`
	SeedSalt            string            `json:"seed_salt"`
}

func (o *RefreshRound1Output) MarshalJSON() ([]byte, error) {
	return json.Marshal(refreshRound1OutputJSON{
		FeldmanCommitments:  encodeBytesSlice(o.FeldmanCommitments),
		PairwiseCommitments: intMap32ToJSON(o.PairwiseCommitments),
		PairwiseSalts:       intMap32ToJSON(o.PairwiseSalts),
		SeedCommitment:      hex.EncodeToString(o.SeedCommitment[:]),
		SeedSalt:            hex.EncodeToString(o.SeedSalt[:]),
	})
}

func (o *RefreshRound1Output) UnmarshalJSON(data []byte) error {
	next := *o
	var j refreshRound1OutputJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	var err error
	next.FeldmanCommitments, err = decodeBytesSlice(j.FeldmanCommitments)
	if err != nil {
		return err
	}
	next.PairwiseCommitments, err = jsonToIntMap32(j.PairwiseCommitments)
	if err != nil {
		return err
	}
	next.PairwiseSalts, err = jsonToIntMap32(j.PairwiseSalts)
	if err != nil {
		return err
	}
	next.SeedCommitment, err = hexToFixed32(j.SeedCommitment)
	if err != nil {
		return err
	}
	next.SeedSalt, err = hexToFixed32(j.SeedSalt)
	if err != nil {
		return err
	}
	*o = next
	return nil
}

// =====================================================================
// RefreshRound2Output
// =====================================================================

type refreshRound2OutputJSON struct {
	SecretShares map[string]string `json:"secret_shares"`
	Seed         string            `json:"seed"`
}

func (o *RefreshRound2Output) MarshalJSON() ([]byte, error) {
	return json.Marshal(refreshRound2OutputJSON{
		SecretShares: intMapBytesToJSON(o.SecretShares),
		Seed:         hex.EncodeToString(o.Seed[:]),
	})
}

func (o *RefreshRound2Output) UnmarshalJSON(data []byte) error {
	next := *o
	var j refreshRound2OutputJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	var err error
	next.SecretShares, err = jsonToIntMapBytes(j.SecretShares)
	if err != nil {
		return err
	}
	next.Seed, err = hexToFixed16(j.Seed)
	if err != nil {
		return err
	}
	*o = next
	return nil
}

// =====================================================================
// SignerSetup — the sync.RWMutex is excluded from serialization
// =====================================================================

type signerSetupJSON struct {
	Version     int                             `json:"version"`
	MyID        int                             `json:"my_id"`
	AllIDs      []int                           `json:"all_ids"`
	Share       string                          `json:"share"`
	PubKey      string                          `json:"pub_key"`
	Threshold   int                             `json:"threshold"`
	AliceBaseOT map[string]*BaseOTReceiverSeeds `json:"alice_base_ot"`
	BobBaseOT   map[string]*BaseOTSenderSeeds   `json:"bob_base_ot"`
	FZeroSeeds  map[string]string               `json:"fzero_seeds"`
	Blacklist   map[string]bool                 `json:"blacklist"`
	Epoch       int                             `json:"epoch"`
	SessionIDs  map[string]int                  `json:"session_ids"`
}

func (s *SignerSetup) MarshalJSON() ([]byte, error) {
	bl := make(map[string]bool, len(s.Blacklist))
	for k, v := range s.Blacklist {
		bl[strconv.Itoa(k)] = v
	}
	sessions := make(map[string]int, len(s.SessionIDs))
	for k, v := range s.SessionIDs {
		sessions[k] = v
	}
	return json.Marshal(signerSetupJSON{
		Version:     SetupWireVersion,
		MyID:        s.MyID,
		AllIDs:      s.AllIDs,
		Share:       scalarToHex(&s.Share),
		PubKey:      hex.EncodeToString(s.PubKey),
		Threshold:   s.Threshold,
		AliceBaseOT: intMapKeys(s.AliceBaseOT),
		BobBaseOT:   intMapKeys(s.BobBaseOT),
		FZeroSeeds:  intMap16ToJSON(s.FZeroSeeds),
		Blacklist:   bl,
		Epoch:       s.Epoch,
		SessionIDs:  sessions,
	})
}

func (s *SignerSetup) UnmarshalJSON(data []byte) error {
	var j signerSetupJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	if j.Version != SetupWireVersion {
		return fmt.Errorf("dkls23 SignerSetup: unsupported wire format version %d (want %d)", j.Version, SetupWireVersion)
	}
	var next SignerSetup
	next.MyID = j.MyID
	next.AllIDs = j.AllIDs
	next.Threshold = j.Threshold
	next.Epoch = j.Epoch

	var err error
	next.Share, err = hexToScalar(j.Share)
	if err != nil {
		return err
	}
	next.PubKey, err = hex.DecodeString(j.PubKey)
	if err != nil {
		return err
	}
	next.AliceBaseOT, err = stringMapKeys(j.AliceBaseOT)
	if err != nil {
		return err
	}
	next.BobBaseOT, err = stringMapKeys(j.BobBaseOT)
	if err != nil {
		return err
	}
	next.FZeroSeeds, err = jsonToIntMap16(j.FZeroSeeds)
	if err != nil {
		return err
	}
	next.Blacklist = make(map[int]bool, len(j.Blacklist))
	for k, v := range j.Blacklist {
		id, err := strconv.Atoi(k)
		if err != nil {
			return err
		}
		next.Blacklist[id] = v
	}
	next.SessionIDs = make(map[string]int, len(j.SessionIDs))
	for sigID, stage := range j.SessionIDs {
		if sigID == "" || stage < sessionRound1Done || stage > sessionRound3Done {
			return fmt.Errorf("dkls23 SignerSetup: invalid session_ids entry %q: %d", sigID, stage)
		}
		next.SessionIDs[sigID] = stage
	}
	// Keep the receiver's mutex and publish the replacement only after every
	// field is decoded. Failed imports leave active sessions and refresh intact.
	s.mu.Lock()
	defer s.mu.Unlock()
	s.MyID = next.MyID
	s.AllIDs = next.AllIDs
	s.Threshold = next.Threshold
	s.Epoch = next.Epoch
	s.Share = next.Share
	s.PubKey = next.PubKey
	s.AliceBaseOT = next.AliceBaseOT
	s.BobBaseOT = next.BobBaseOT
	s.FZeroSeeds = next.FZeroSeeds
	s.Blacklist = next.Blacklist
	s.SessionIDs = next.SessionIDs
	return nil
}
