// Package authz gates every active pipeline. A run needs a loadable scope file
// and an explicit authorization flag; without both, huntx refuses to send traffic.
package authz

import (
	"errors"
	"fmt"

	"github.com/talkdedsec/tlk-huntx/internal/scope"
)

type Config struct {
	Authorized bool
	ScopePath  string
	DryRun     bool
}

func (c Config) Verify() (*scope.Scope, error) {
	if c.ScopePath == "" {
		return nil, errors.New("no scope file: pass --scope <file.json>")
	}
	s, err := scope.Load(c.ScopePath)
	if err != nil {
		return nil, fmt.Errorf("scope: %w", err)
	}
	if !c.Authorized {
		return nil, errors.New("refusing to run without --authorized: only test targets you have permission to test")
	}
	return s, nil
}
