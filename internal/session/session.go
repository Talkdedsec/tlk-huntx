// Package session loads the identities used for access-control testing: each named
// role carries the headers (auth token, cookie) that authenticate it. The BOLA
// engine replays one request as different identities to prove broken authorization.
package session

import (
	"encoding/json"
	"fmt"
	"os"
)

type Identity struct {
	Headers map[string]string `json:"headers"`
}

func Load(path string) (map[string]Identity, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ids map[string]Identity
	if err := json.Unmarshal(b, &ids); err != nil {
		return nil, fmt.Errorf("parse identities %s: %w", path, err)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("no identities in %s", path)
	}
	return ids, nil
}
