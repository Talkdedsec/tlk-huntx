// Package recon discovers the attack surface. Passive sources query third-party
// OSINT (crt.sh, the Wayback Machine, AlienVault OTX) with a plain client — they
// are not the target. Everything a source returns is filtered through scope before
// any of it is probed.
package recon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

func PassiveSubdomains(ctx context.Context, domain string, client *http.Client) ([]string, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	seen := map[string]struct{}{}
	var firstErr error

	for _, src := range []struct {
		name string
		fn   func(context.Context, string, *http.Client) ([]string, error)
	}{
		{"crtsh", crtSh},
		{"wayback", wayback},
		{"otx", otx},
		{"hackertarget", hackerTarget},
	} {
		hosts, err := src.fn(ctx, domain, client)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", src.name, err)
			}
			continue
		}
		for _, h := range hosts {
			if h = cleanHost(h, domain); h != "" {
				seen[h] = struct{}{}
			}
		}
	}

	out := make([]string, 0, len(seen))
	for h := range seen {
		out = append(out, h)
	}
	sort.Strings(out)
	if len(out) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

func cleanHost(h, domain string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimPrefix(h, "*.")
	h = strings.TrimSuffix(h, ".")
	if h == "" || strings.ContainsAny(h, " /@") {
		return ""
	}
	if h != domain && !strings.HasSuffix(h, "."+domain) {
		return ""
	}
	return h
}

func crtSh(ctx context.Context, domain string, client *http.Client) ([]string, error) {
	u := "https://crt.sh/?q=%25." + url.QueryEscape(domain) + "&output=json"
	body, err := get(ctx, client, u)
	if err != nil {
		return nil, err
	}
	return parseCrtSh(body)
}

func parseCrtSh(r io.Reader) ([]string, error) {
	var rows []struct {
		NameValue  string `json:"name_value"`
		CommonName string `json:"common_name"`
	}
	if err := json.NewDecoder(r).Decode(&rows); err != nil {
		return nil, err
	}
	var out []string
	for _, row := range rows {
		out = append(out, strings.Split(row.NameValue, "\n")...)
		if row.CommonName != "" {
			out = append(out, row.CommonName)
		}
	}
	return out, nil
}

func wayback(ctx context.Context, domain string, client *http.Client) ([]string, error) {
	u := "https://web.archive.org/cdx/search/cdx?url=*." + url.QueryEscape(domain) +
		"/*&output=json&fl=original&collapse=urlkey&limit=10000"
	body, err := get(ctx, client, u)
	if err != nil {
		return nil, err
	}
	return parseWayback(body)
}

func parseWayback(r io.Reader) ([]string, error) {
	var rows [][]string
	if err := json.NewDecoder(r).Decode(&rows); err != nil {
		return nil, err
	}
	var out []string
	for i, row := range rows {
		if i == 0 || len(row) == 0 {
			continue // header row
		}
		if u, err := url.Parse(row[0]); err == nil && u.Host != "" {
			out = append(out, u.Hostname())
		}
	}
	return out, nil
}

func otx(ctx context.Context, domain string, client *http.Client) ([]string, error) {
	u := "https://otx.alienvault.com/api/v1/indicators/domain/" + url.PathEscape(domain) + "/passive_dns"
	body, err := get(ctx, client, u)
	if err != nil {
		return nil, err
	}
	return parseOTX(body)
}

func parseOTX(r io.Reader) ([]string, error) {
	var payload struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := json.NewDecoder(r).Decode(&payload); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(payload.PassiveDNS))
	for _, p := range payload.PassiveDNS {
		out = append(out, p.Hostname)
	}
	return out, nil
}

func hackerTarget(ctx context.Context, domain string, client *http.Client) ([]string, error) {
	u := "https://api.hackertarget.com/hostsearch/?q=" + url.QueryEscape(domain)
	body, err := get(ctx, client, u)
	if err != nil {
		return nil, err
	}
	return parseHackerTarget(body)
}

// parseHackerTarget reads the "hostname,ip" CSV lines the API returns, taking the
// hostname from each. An error/quota line (no comma) yields nothing.
func parseHackerTarget(r io.Reader) ([]string, error) {
	b, err := io.ReadAll(io.LimitReader(r, 8<<20))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if i := strings.IndexByte(line, ','); i > 0 {
			out = append(out, line[:i])
		}
	}
	return out, nil
}

func get(ctx context.Context, client *http.Client, rawurl string) (io.Reader, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", rawurl, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "huntx")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(b), nil
}
