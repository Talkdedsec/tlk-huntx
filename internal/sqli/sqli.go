// Package sqli detects error-based SQL injection: it sends a quote into each
// parameter and looks for a database error message that was not in the baseline
// response. It probes with quotes only — it proves the input reaches a query
// unsafely, it does not run an injection like OR 1=1.
package sqli

import (
	"context"
	"net/url"
	"regexp"

	"github.com/talkdedsec/tlk-huntx/internal/fetch"
	"github.com/talkdedsec/tlk-huntx/internal/finding"
)

var errorSigs = []struct {
	db string
	re *regexp.Regexp
}{
	{"MySQL", regexp.MustCompile(`(?i)you have an error in your SQL syntax|mysql_fetch|MySqlException|MySQLSyntaxErrorException|valid MySQL result`)},
	{"PostgreSQL", regexp.MustCompile(`(?i)PSQLException|PostgreSQL.{0,30}(ERROR|error)|pg_query\(\)|syntax error at or near`)},
	{"MSSQL", regexp.MustCompile(`(?i)Unclosed quotation mark|Microsoft OLE DB Provider for SQL Server|SqlException|Incorrect syntax near`)},
	{"Oracle", regexp.MustCompile(`(?i)ORA-\d{5}|quoted string not properly terminated`)},
	{"SQLite", regexp.MustCompile(`(?i)SQLite3::|SQLiteException|sqlite3\.OperationalError|unrecognized token`)},
}

var payloads = []string{"'", "\"", "')"}

func Test(ctx context.Context, c *fetch.Client, rawurl string, extra []string) []finding.Finding {
	names, base := paramNames(rawurl, extra)
	if base == nil {
		return nil
	}
	baseBody := getBody(ctx, c, rawurl)

	var out []finding.Finding
	for name := range names {
		if f, ok := testParam(ctx, c, rawurl, name, baseBody); ok {
			out = append(out, f)
		}
	}
	return out
}

func testParam(ctx context.Context, c *fetch.Client, rawurl, name, baseBody string) (finding.Finding, bool) {
	for _, p := range payloads {
		target := setParam(rawurl, name, "1"+p)
		body := getBody(ctx, c, target)
		if body == "" {
			continue
		}
		for _, sig := range errorSigs {
			if sig.re.MatchString(body) && !sig.re.MatchString(baseBody) {
				f := finding.Finding{
					Target:     rawurl,
					Type:       "Error-based SQL injection (" + sig.db + ")",
					TemplateID: "sqli-error",
					Severity:   finding.High,
					Confidence: 80,
					MatchedAt:  target,
					CWE:        "CWE-89",
					Extracted:  map[string]string{"parameter": name, "dbms": sig.db},
					Evidence:   finding.Evidence{Request: "GET " + target, Response: sig.re.FindString(body)},
					Repro:      "curl -s " + target,
				}
				f.Finalize([]string{name})
				return f, true
			}
		}
	}
	return finding.Finding{}, false
}

func paramNames(rawurl string, extra []string) (map[string]bool, *url.URL) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, nil
	}
	names := map[string]bool{}
	for name := range u.Query() {
		names[name] = true
	}
	for _, name := range extra {
		if name != "" {
			names[name] = true
		}
	}
	if len(names) == 0 {
		return nil, nil
	}
	return names, u
}

func getBody(ctx context.Context, c *fetch.Client, rawurl string) string {
	resp, err := c.Do(ctx, "GET", rawurl, nil)
	if err != nil || resp == nil || resp.DryRun {
		return ""
	}
	return string(resp.Body)
}

func setParam(rawurl, name, value string) string {
	u, err := url.Parse(rawurl)
	if err != nil {
		return rawurl
	}
	q := u.Query()
	q.Set(name, value)
	u.RawQuery = q.Encode()
	return u.String()
}
