// Package crawl mines endpoints and parameters out of HTML and JavaScript: paths
// referenced in fetch/axios calls and links, query and form parameter names, and
// same-host script bundles worth pulling for more of the same. It feeds the attack
// surface graph the routes a passive scan would otherwise miss.
package crawl

import (
	"context"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/talkdedsec/tlk-huntx/internal/fetch"
)

var (
	pathRe = regexp.MustCompile(`["'` + "`" + `](/[A-Za-z0-9_\-/.]{1,120})`)
	absRe  = regexp.MustCompile(`https?://[A-Za-z0-9_.\-]+(/[A-Za-z0-9_\-./]{0,120})`)
	// query keys are read only from quoted URL-like tokens (href/fetch/axios), not
	// from bare ?x= sequences that litter minified JS and would produce junk params.
	urlQueryRe = regexp.MustCompile(`["'` + "`" + `]([^"'` + "`" + `\s<>]*\?[^"'` + "`" + `\s<>]{1,300})["'` + "`" + `]`)
	paramKeyRe = regexp.MustCompile(`^[A-Za-z0-9_\-]{1,40}$`)
	inputRe    = regexp.MustCompile(`(?i)<(?:input|select|textarea|button)\b[^>]*?\bname\s*=\s*["']([A-Za-z0-9_\-\[\]]{1,40})["']`)
	scriptRe   = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']([^"']+)["']`)
	robotsRe   = regexp.MustCompile(`(?im)^\s*(?:allow|disallow):\s*(/\S*)`)
	locRe      = regexp.MustCompile(`(?i)<loc>\s*([^<\s]+)\s*</loc>`)
)

// RobotsPaths returns the Allow/Disallow paths declared in a robots.txt — often a
// direct map of the paths the owner most wants hidden.
func RobotsPaths(body string) []string {
	set := map[string]bool{}
	for _, m := range robotsRe.FindAllStringSubmatch(body, -1) {
		set[m[1]] = true
	}
	return sortedKeys(set)
}

// SitemapURLs returns the <loc> URLs from a sitemap.xml.
func SitemapURLs(body string) []string {
	set := map[string]bool{}
	for _, m := range locRe.FindAllStringSubmatch(body, -1) {
		set[m[1]] = true
	}
	return sortedKeys(set)
}

func Endpoints(body string) []string {
	set := map[string]bool{}
	for _, m := range pathRe.FindAllStringSubmatch(body, -1) {
		set[m[1]] = true
	}
	for _, m := range absRe.FindAllStringSubmatch(body, -1) {
		if m[1] != "" {
			set[m[1]] = true
		}
	}
	return sortedKeys(set)
}

func Params(body string) []string {
	set := map[string]bool{}
	for _, m := range inputRe.FindAllStringSubmatch(body, -1) {
		set[m[1]] = true
	}
	for _, m := range urlQueryRe.FindAllStringSubmatch(body, -1) {
		path, query, _ := strings.Cut(m[1], "?")
		if !strings.Contains(path, "/") { // a real URL path, not a code fragment like f?g=h
			continue
		}
		for _, pair := range strings.Split(query, "&") {
			k, _, _ := strings.Cut(pair, "=")
			if paramKeyRe.MatchString(k) && strings.IndexFunc(k, isNonDigit) >= 0 {
				set[k] = true
			}
		}
	}
	return sortedKeys(set)
}

// ScriptSrcs returns same-host script URLs referenced by the page, resolved absolute.
func ScriptSrcs(body, base string) []string {
	b, err := url.Parse(base)
	if err != nil {
		return nil
	}
	set := map[string]bool{}
	for _, m := range scriptRe.FindAllStringSubmatch(body, -1) {
		ref, err := b.Parse(m[1])
		if err != nil {
			continue
		}
		if ref.Host == b.Host && (ref.Scheme == "http" || ref.Scheme == "https") {
			set[ref.String()] = true
		}
	}
	return sortedKeys(set)
}

type Result struct {
	Endpoints []string
	Params    []string
}

// Run fetches the page and up to a handful of its same-host scripts through the
// gated client, merging every endpoint and parameter it can extract.
func Run(ctx context.Context, c *fetch.Client, base string) Result {
	endpoints := map[string]bool{}
	params := map[string]bool{}

	resp, err := c.Do(ctx, "GET", base, nil)
	if err != nil || resp == nil || resp.DryRun {
		return Result{}
	}
	body := string(resp.Body)
	collect(endpoints, Endpoints(body))
	collect(params, Params(body))

	if r, err := c.Do(ctx, "GET", base+"/robots.txt", nil); err == nil && r != nil && !r.DryRun && r.Status == 200 {
		collect(endpoints, RobotsPaths(string(r.Body)))
	}
	if r, err := c.Do(ctx, "GET", base+"/sitemap.xml", nil); err == nil && r != nil && !r.DryRun && r.Status == 200 {
		for _, loc := range SitemapURLs(string(r.Body)) {
			if pu, err := url.Parse(loc); err == nil && pu.Path != "" {
				collect(endpoints, []string{pu.Path})
			}
		}
	}

	scripts := ScriptSrcs(body, base)
	if len(scripts) > 15 {
		scripts = scripts[:15]
	}
	for _, src := range scripts {
		if ctx.Err() != nil {
			break
		}
		r, err := c.Do(ctx, "GET", src, nil)
		if err != nil || r == nil || r.DryRun {
			continue
		}
		js := string(r.Body)
		collect(endpoints, Endpoints(js))
		collect(params, Params(js))
	}
	return Result{Endpoints: sortedKeys(endpoints), Params: sortedKeys(params)}
}

func isNonDigit(r rune) bool { return r < '0' || r > '9' }

func collect(set map[string]bool, items []string) {
	for _, i := range items {
		set[i] = true
	}
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
