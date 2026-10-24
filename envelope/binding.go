package envelope

// Binding identifies the trusted owner and epoch of persisted private state.
// Obtain it from the application's key registry, not an unauthenticated header.
// Protocol packages supply the protocol, kind, version and operation fields.
type Binding struct {
	PublicKey []byte
	PartyID   int
	Epoch     int
}
