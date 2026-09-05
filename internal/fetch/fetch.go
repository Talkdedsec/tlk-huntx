// Package fetch is the only way huntx talks to a target. Every request passes the
// scope gate, the rate limiter, and the blast-radius guard before a byte leaves.
// Active modules must use this client and never net/http directly against a target.
package fetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/talkdedsec/tlk-huntx/internal/blastradius"
	"github.com/talkdedsec/tlk-huntx/internal/ratelimit"
	"github.com/talkdedsec/tlk-huntx/internal/scope"
)

var (
	ErrOutOfScope    = errors.New("out of scope")
	ErrMethodBlocked = errors.New("method not allowed by scope")
	ErrForbiddenPath = errors.New("forbidden path")
	ErrBudget        = errors.New("blast-radius denied")
)

type Client struct {
	scope   *scope.Scope
	lim     *ratelimit.Limiter
	guard   *blastradius.Guard
	http    *http.Client
	dryRun  bool
	ua      string
	maxBody int64
}

type Response struct {
	URL     string
	Status  int
	Header  http.Header
	Body    []byte
	Elapsed time.Duration
	DryRun  bool
}

func New(s *scope.Scope, lim *ratelimit.Limiter, guard *blastradius.Guard, dryRun bool) *Client {
	return &Client{
		scope:  s,
		lim:    lim,
		guard:  guard,
		dryRun: dryRun,
		http: &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		ua:      "huntx",
		maxBody: 2 << 20,
	}
}

func (c *Client) Do(ctx context.Context, method, rawurl string, body io.Reader) (*Response, error) {
	return c.DoReq(ctx, method, rawurl, nil, body)
}

func (c *Client) DoReq(ctx context.Context, method, rawurl string, headers map[string]string, body io.Reader) (*Response, error) {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "GET"
	}
	u, err := url.Parse(rawurl)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("bad url %q", rawurl)
	}
	if d := c.scope.Check(rawurl); !d.Allowed {
		return nil, fmt.Errorf("%w: %s (%s)", ErrOutOfScope, u.Host, d.Reason)
	}
	if !c.scope.AllowsMethod(method) {
		return nil, fmt.Errorf("%w: %s", ErrMethodBlocked, method)
	}
	if !c.scope.AllowsPath(u.Path) {
		return nil, fmt.Errorf("%w: %s", ErrForbiddenPath, u.Path)
	}
	if c.dryRun {
		return &Response{URL: rawurl, DryRun: true}, nil
	}
	if dec := c.guard.Allow(method); !dec.Allowed {
		return nil, fmt.Errorf("%w: %s", ErrBudget, dec.Reason)
	}

	release, err := c.lim.Acquire(ctx, u.Host)
	if err != nil {
		return nil, err
	}
	defer release()

	req, err := http.NewRequestWithContext(ctx, method, rawurl, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.ua)
	for k, v := range headers {
		if strings.EqualFold(k, "Host") {
			req.Host = v // Host must be set on the request, not the header map
			continue
		}
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(io.LimitReader(resp.Body, c.maxBody))
	if resp.StatusCode == http.StatusTooManyRequests {
		c.lim.Penalize(u.Host, 10*time.Second)
	}
	return &Response{
		URL:     rawurl,
		Status:  resp.StatusCode,
		Header:  resp.Header,
		Body:    b,
		Elapsed: time.Since(start),
	}, nil
}
