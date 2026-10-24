package shared

import (
	"context"
	"github.com/chrisalmeida/go-mpc/session"
)

// Guard is a demo's online, in-memory operation controller. Cold workflows use
// session.Advance in Resumable mode instead of retaining Memory across transfers.
type Guard struct {
	Store  session.Store
	Scope  session.Scope
	Memory session.Memory
}

func (g *Guard) Advance(id session.ID, round int, parties []int, compute session.Compute) ([]byte, error) {
	key, err := session.InspectKey(context.Background(), g.Store, g.Scope)
	if err != nil {
		return nil, err
	}
	req := session.Request{Version: key.Version, ID: id, Round: round, Participants: parties}
	receipt, err := g.Memory.Advance(context.Background(), g.Store, g.Scope, req, compute)
	if err != nil {
		return nil, err
	}
	return receipt.Output, nil
}
func (g *Guard) Activate(operation string) error {
	key, err := session.InspectKey(context.Background(), g.Store, g.Scope)
	if err != nil {
		return err
	}
	_, err = session.Activate(context.Background(), g.Store, g.Scope, key.Version, operation)
	return err
}
func (g *Guard) ID(kind session.Kind, value string) (session.ID, error) {
	key, err := session.InspectKey(context.Background(), g.Store, g.Scope)
	return session.ID{Kind: kind, Epoch: key.Epoch, Value: value}, err
}
