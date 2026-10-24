//go:build !darwin && !linux

package shared

import (
	"context"
	"fmt"
)

func lockScope(context.Context, string) (func(), error) {
	return nil, fmt.Errorf("example file store: kernel locking implemented for Linux and macOS only; supply a session.Store for this platform")
}
