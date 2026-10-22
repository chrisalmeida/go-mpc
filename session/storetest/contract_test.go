package storetest_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/chrisalmeida/go-mpc/session"
	"github.com/chrisalmeida/go-mpc/session/storetest"
)

func TestModelStorageContract(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T) (session.Store, func() session.Store) {
		model := &storetest.Model{}
		return model.Open(), model.Open
	})
}

func TestConformanceRejectsDestructiveRollback(t *testing.T) {
	const faultEnv = "GO_MPC_STORETEST_DESTRUCTIVE_ROLLBACK"
	if fault := os.Getenv(faultEnv); fault != "" {
		if fault != "error" && fault != "panic" {
			t.Fatal("unknown rollback fault")
		}
		storetest.Run(t, func(t *testing.T) (session.Store, func() session.Store) {
			state := &destructiveRollbackState{fault: fault, models: make(map[session.Scope]*storetest.Model)}
			open := func() session.Store { return &destructiveRollbackConnection{state: state} }
			return open(), open
		})
		return
	}
	t.Parallel()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"error", "panic"} {
		t.Run(fault, func(t *testing.T) {
			t.Parallel()
			// The deliberately broken backend must fail Run. A subprocess lets
			// us inspect those expected testing.T failures without failing this test.
			cmd := exec.Command(executable, "-test.run=^TestConformanceRejectsDestructiveRollback$", "-test.v")
			cmd.Env = append(os.Environ(), faultEnv+"="+fault)
			output, err := cmd.CombinedOutput()
			var exitError *exec.ExitError
			if !errors.As(err, &exitError) {
				t.Fatalf("conformance did not reject destructive rollback: %v\n%s", err, output)
			}
			for _, message := range []string{
				"committed key changed after rollback",
				"committed session changed after rollback",
				"committed nonce reservation lost after rollback",
			} {
				if !strings.Contains(string(output), message) {
					t.Fatalf("missing conformance failure %q:\n%s", message, output)
				}
			}
		})
	}
}

// This test-only backend violates rollback by erasing the scope's previously
// committed records on either a callback error or a panic. All other behavior
// comes from Model, so its rejection exercises the populated rollback checks.
type destructiveRollbackState struct {
	mu     sync.Mutex
	fault  string
	models map[session.Scope]*storetest.Model
}

type destructiveRollbackConnection struct{ state *destructiveRollbackState }

func (c *destructiveRollbackConnection) Transact(ctx context.Context, scope session.Scope, fn func(session.Transaction) error) error {
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	model := c.state.models[scope]
	if model == nil {
		model = &storetest.Model{}
		c.state.models[scope] = model
	}
	defer func() {
		if value := recover(); value != nil {
			if c.state.fault == "panic" {
				c.state.models[scope] = &storetest.Model{}
			}
			panic(value)
		}
	}()
	err := model.Open().Transact(ctx, scope, fn)
	if err != nil && c.state.fault == "error" {
		c.state.models[scope] = &storetest.Model{}
	}
	return err
}
