package envelope

import (
	"encoding/binary"
	"math"
	"slices"
)

// Protocol tags and blob kinds identify the existing protocol payloads. They
// are local container metadata, not protocol domain-separation tags.
const (
	DKLS23        = "dkls23"
	FROST         = "frost"
	Setup         = "setup"
	Key           = "key"
	Signer        = "signer"
	Sign1         = "sign-1"
	Sign2         = "sign-2"
	Refresh1      = "refresh-1"
	Refresh2      = "refresh-2"
	RefreshOutput = "refresh-output"
	SignOutput    = "sign-output"
)

// Context binds a payload to a protocol, kind, payload wire version, group key,
// local party and key epoch. Session blobs also bind an opaque operation ID and
// completed round. The protocol wrapper composes it from validated state.
//
// Its canonical encoding is eight uint16-length-prefixed fields in declaration
// order. Strings and PublicKey are raw bytes; integers are unsigned big-endian:
// WireVersion, PartyID and Round use four bytes; Epoch uses eight. The complete
// encoding fits uint16. Key kinds require empty OperationID and round zero;
// sign-1/refresh-1 require an operation and round one; sign-2/refresh-2 use round
// two. refresh-output encrypts secret round-2 refresh messages. Only DKLS23 has setup/sign-2; key/signer are FROST kinds.
//
// Validation checks metadata shape and encoded public-key width, not curve
// membership, payload semantics or its correspondence to this context. Protocol
// codecs must perform those checks. Context is public, including OperationID.
type Context struct {
	Protocol    string
	Kind        string
	WireVersion uint32
	PublicKey   []byte
	PartyID     int
	Epoch       int
	OperationID string
	Round       int
}

var contextFields = [...]string{"protocol", "kind", "wire_version", "public_key", "party_id", "epoch", "operation_id", "round"}

func validateContext(c Context, op string) error {
	bad := func(field string) error { return failure(op, field, ErrInvalidContext) }
	width := 32
	if c.Protocol == DKLS23 {
		width = 33
	} else if c.Protocol != FROST {
		return bad("protocol")
	}
	round := 0
	switch c.Kind {
	case Setup:
		if c.Protocol != DKLS23 {
			return bad("kind")
		}
	case Key, Signer:
		if c.Protocol != FROST {
			return bad("kind")
		}
	case Sign1, Refresh1:
		round = 1
	case Sign2:
		if c.Protocol != DKLS23 {
			return bad("kind")
		}
		round = 2
	case SignOutput:
		round = c.Round
		last := 3
		if c.Protocol == FROST {
			last = 2
		}
		if round < 1 || round > last {
			return bad("round")
		}
	case RefreshOutput:
		round = c.Round
		if round < 1 || round > 2 {
			return bad("round")
		}
	case Refresh2:
		round = 2
	default:
		return bad("kind")
	}
	if c.WireVersion == 0 {
		return bad("wire_version")
	}
	if len(c.PublicKey) != width {
		return bad("public_key")
	}
	if c.PartyID < 1 || c.PartyID > math.MaxInt32 {
		return bad("party_id")
	}
	if c.Epoch < 0 {
		return bad("epoch")
	}
	if c.Round != round {
		return bad("round")
	}
	if (c.OperationID == "") != (round == 0) || len(c.OperationID) > math.MaxUint16 {
		return bad("operation_id")
	}
	return nil
}

func encodeContext(c Context, op string) ([]byte, error) {
	if err := validateContext(c, op); err != nil {
		return nil, err
	}
	fields := [][]byte{[]byte(c.Protocol), []byte(c.Kind), binary.BigEndian.AppendUint32(nil, c.WireVersion), c.PublicKey,
		binary.BigEndian.AppendUint32(nil, uint32(c.PartyID)), binary.BigEndian.AppendUint64(nil, uint64(c.Epoch)), []byte(c.OperationID), binary.BigEndian.AppendUint32(nil, uint32(c.Round))}
	total := 2 * len(fields)
	for _, field := range fields {
		total += len(field)
	}
	if total > math.MaxUint16 {
		return nil, failure(op, "context", ErrInvalidContext)
	}
	out := make([]byte, 0, total)
	for _, field := range fields {
		out = binary.BigEndian.AppendUint16(out, uint16(len(field)))
		out = append(out, field...)
	}
	return out, nil
}

// decodeContext consumes exactly eight fields from the bounded clear header.
// The framing parser separately forbids trailing bytes.
func decodeContext(data []byte, op string) (Context, int, error) {
	var fields [len(contextFields)][]byte
	consumed := 0
	for i, name := range contextFields {
		if len(data)-consumed < 2 {
			return Context{}, 0, failure(op, name, ErrInvalidEnvelope)
		}
		n := int(binary.BigEndian.Uint16(data[consumed:]))
		consumed += 2
		if n > len(data)-consumed {
			return Context{}, 0, failure(op, name, ErrInvalidEnvelope)
		}
		fields[i] = data[consumed : consumed+n]
		consumed += n
	}
	for _, i := range []int{2, 4, 5, 7} {
		width := 4
		if i == 5 {
			width = 8
		}
		if len(fields[i]) != width {
			return Context{}, 0, failure(op, contextFields[i], ErrInvalidEnvelope)
		}
	}
	party, epoch, round := binary.BigEndian.Uint32(fields[4]), binary.BigEndian.Uint64(fields[5]), binary.BigEndian.Uint32(fields[7])
	if party > math.MaxInt32 {
		return Context{}, 0, failure(op, "party_id", ErrInvalidContext)
	}
	if epoch > uint64(math.MaxInt) {
		return Context{}, 0, failure(op, "epoch", ErrInvalidContext)
	}
	if uint64(round) > uint64(math.MaxInt) {
		return Context{}, 0, failure(op, "round", ErrInvalidContext)
	}
	c := Context{Protocol: string(fields[0]), Kind: string(fields[1]), WireVersion: binary.BigEndian.Uint32(fields[2]),
		PublicKey: slices.Clone(fields[3]), PartyID: int(party), Epoch: int(epoch), OperationID: string(fields[6]), Round: int(round)}
	if err := validateContext(c, op); err != nil {
		return Context{}, 0, err
	}
	return c, consumed, nil
}
