package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/talkdedsec/tlk-huntx/internal/agent"
	"github.com/talkdedsec/tlk-huntx/internal/apidisco"
	"github.com/talkdedsec/tlk-huntx/internal/authz"
	"github.com/talkdedsec/tlk-huntx/internal/cmdi"
	"github.com/talkdedsec/tlk-huntx/internal/collaborator"
	"github.com/talkdedsec/tlk-huntx/internal/crawl"
	"github.com/talkdedsec/tlk-huntx/internal/dashboard"
	"github.com/talkdedsec/tlk-huntx/internal/distributed"
	"github.com/talkdedsec/tlk-huntx/internal/engine"
	"github.com/talkdedsec/tlk-huntx/internal/feedback"
	"github.com/talkdedsec/tlk-huntx/internal/finding"
	"github.com/talkdedsec/tlk-huntx/internal/fuzz"
	"github.com/talkdedsec/tlk-huntx/internal/graph"
	"github.com/talkdedsec/tlk-huntx/internal/greybox"
	"github.com/talkdedsec/tlk-huntx/internal/hostheader"
	"github.com/talkdedsec/tlk-huntx/internal/lfi"
	"github.com/talkdedsec/tlk-huntx/internal/mcp"
	"github.com/talkdedsec/tlk-huntx/internal/monitor"
	"github.com/talkdedsec/tlk-huntx/internal/notify"
	"github.com/talkdedsec/tlk-huntx/internal/openredirect"
	"github.com/talkdedsec/tlk-huntx/internal/recon"
	"github.com/talkdedsec/tlk-huntx/internal/reflectx"
	"github.com/talkdedsec/tlk-huntx/internal/report"
	"github.com/talkdedsec/tlk-huntx/internal/sarif"
	"github.com/talkdedsec/tlk-huntx/internal/scope"
	"github.com/talkdedsec/tlk-huntx/internal/session"
	"github.com/talkdedsec/tlk-huntx/internal/sqli"
	"github.com/talkdedsec/tlk-huntx/internal/ssrf"
	"github.com/talkdedsec/tlk-huntx/internal/ssti"
	"github.com/talkdedsec/tlk-huntx/internal/template"
	"github.com/talkdedsec/tlk-huntx/internal/verify"
)

// Version is overridable at build time via -ldflags "-X ...cli.Version=vX.Y.Z".
var Version = "0.1.0"

var banner = `huntx ` + Version + ` — bug bounty engine (recon · scan · verify · report)`

const (
	ansiReset = "\x1b[0m"
	ansiSteel = "\x1b[38;2;173;181;189m"
	ansiRed   = "\x1b[38;2;227;38;54m"
	ansiDim   = "\x1b[38;2;120;130;140m"
)

func color() bool { return os.Getenv("NO_COLOR") == "" }

func paint(code, s string) string {
	if !color() {
		return s
	}
	return code + s + ansiReset
}

// bigBanner renders the huntx wordmark (steel "hunt" + red "x") with the tagline,
// echoing the logo. Colors drop out under NO_COLOR.
func bigBanner() string {
	hunt := []string{
		"██╗  ██╗██╗   ██╗███╗   ██╗████████╗",
		"██║  ██║██║   ██║████╗  ██║╚══██╔══╝",
		"███████║██║   ██║██╔██╗ ██║   ██║   ",
		"██╔══██║██║   ██║██║╚██╗██║   ██║   ",
		"██║  ██║╚██████╔╝██║ ╚████║   ██║   ",
		"╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ",
	}
	x := []string{
		"██╗  ██╗",
		"╚██╗██╔╝",
		" ╚███╔╝ ",
		" ██╔██╗ ",
		"██╔╝ ██╗",
		"╚═╝  ╚═╝",
	}
	var b strings.Builder
	b.WriteString("\n")
	for i := range hunt {
		b.WriteString("  " + paint(ansiSteel, hunt[i]) + paint(ansiRed, x[i]) + "\n")
	}
	b.WriteString("  " + paint(ansiRed, strings.Repeat("─", 36)) + paint(ansiDim, strings.Repeat("─", 8)) + "\n")
	b.WriteString("  " + paint(ansiRed, "⊕ ") + paint(ansiDim, "AUTHORIZED ATTACK SURFACE RECON & TRIAGE") + "\n")
	arrow := paint(ansiRed, " → ")
	b.WriteString("  " + paint(ansiSteel, "recon") + arrow + paint(ansiSteel, "scan") +
		arrow + paint(ansiSteel, "validate") + arrow + paint(ansiSteel, "report") + "\n")
	b.WriteString("  " + paint(ansiDim, "talkdedsec/tlk-huntx") + paint(ansiRed, " · ") + paint(ansiDim, Version) + "\n")
	return b.String()
}

const graphFile = "huntx.graph.json"
const findingsFile = "huntx.findings.jsonl"
const feedbackFile = "huntx.feedback.json"

type globalFlags struct {
	scopePath          string
	authorized         bool
	dryRun             bool
	rps                float64
	burst              int
	concurrency        int
	maxRequests        int
	allowStateChanging bool
	output             string
	templatesDir       string
	verify             bool
	listen             string
	base               string
	interval           string
	notify             string
	identities         string
	owner              string
	src                string
	coordinator        string
	wordlist           string
	minSeverity        string
}

func (g *globalFlags) opts(s *scope.Scope) engine.Options {
	return engine.Options{
		Scope:              s,
		RPS:                g.rps,
		Burst:              g.burst,
		Concurrency:        g.concurrency,
		MaxRequests:        g.maxRequests,
		AllowStateChanging: g.allowStateChanging,
		DryRun:             g.dryRun,
		Verify:             g.verify,
		TemplatesDir:       g.templatesDir,
		Feedback:           feedback.Load(feedbackFile),
		Log:                func(m string) { fmt.Fprintln(os.Stderr, m) },
	}
}

func Execute(args []string) int {
	fs := flag.NewFlagSet("huntx", flag.ContinueOnError)
	g := &globalFlags{}
	fs.StringVar(&g.scopePath, "scope", "", "path to scope file (JSON)")
	fs.BoolVar(&g.authorized, "authorized", false, "confirm you are authorized to test the scope")
	fs.BoolVar(&g.dryRun, "dry-run", false, "plan only, send no requests")
	fs.Float64Var(&g.rps, "rps", 5, "max requests per second per host")
	fs.IntVar(&g.burst, "burst", 0, "rate-limit burst (default: rps)")
	fs.IntVar(&g.concurrency, "concurrency", 10, "global max concurrent requests")
	fs.IntVar(&g.maxRequests, "max-requests", 0, "hard cap on total requests (0 = unlimited)")
	fs.BoolVar(&g.allowStateChanging, "allow-state-changing", false, "permit POST/PUT/DELETE/PATCH")
	fs.StringVar(&g.output, "o", "", "write output to file (default: stdout)")
	fs.StringVar(&g.templatesDir, "templates", "", "extra template directory (loaded alongside built-ins)")
	fs.BoolVar(&g.verify, "verify", false, "deterministically re-confirm each finding (scan)")
	fs.StringVar(&g.listen, "listen", ":8888", "collaborator listen address")
	fs.StringVar(&g.base, "base", "", "collaborator public base URL (default: http://localhost<listen>)")
	fs.StringVar(&g.interval, "interval", "", "monitor: repeat every duration (e.g. 30m); empty = one pass")
	fs.StringVar(&g.notify, "notify", "", "monitor: webhook URL for new hosts/findings (Slack/Discord)")
	fs.StringVar(&g.identities, "identities", "", "bola: JSON file of named identities (role -> headers)")
	fs.StringVar(&g.owner, "owner", "owner", "bola: identity that legitimately owns the resource")
	fs.StringVar(&g.src, "src", "", "greybox: source tree to scan for reachable sinks")
	fs.StringVar(&g.coordinator, "coordinator", "", "worker: coordinator base URL to pull targets from")
	fs.StringVar(&g.wordlist, "wordlist", "", "fuzz: path list file (default: built-in common paths)")
	fs.StringVar(&g.minSeverity, "min-severity", "", "keep only findings at or above this severity (low/medium/high/critical)")
	fs.Usage = func() { usage(fs) }

	positionals, err := parseInterspersed(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) == 0 {
		usage(fs)
		return 2
	}

	cmd, rest := positionals[0], positionals[1:]
	switch cmd {
	case "version":
		fmt.Print(bigBanner())
		return 0
	case "help", "-h", "--help":
		usage(fs)
		return 0
	case "scope":
		return runScope(g, rest)
	case "recon", "run":
		return runRecon(cmd, g, rest)
	case "full":
		return runFull(g, rest)
	case "scan":
		return runScan(g, rest)
	case "monitor":
		return runMonitor(g, rest)
	case "api":
		return runApi(g, rest)
	case "crawl":
		return runCrawl(g, rest)
	case "fuzz":
		return runFuzz(g, rest)
	case "bola", "idor":
		return runBola(g, rest)
	case "reflect", "xss":
		return runReflect(g, rest)
	case "redirect", "openredirect":
		return runRedirect(g, rest)
	case "ssrf":
		return runSSRF(g, rest)
	case "cmdi":
		return runCmdi(g, rest)
	case "sqli":
		return runSQLi(g, rest)
	case "ssti":
		return runSSTI(g, rest)
	case "lfi":
		return runLFI(g, rest)
	case "hostheader", "hhi":
		return runHostHeader(g, rest)
	case "greybox":
		return runGreybox(g)
	case "plan":
		return runPlan(g, rest)
	case "coordinate":
		return runCoordinate(g, rest)
	case "worker":
		return runWorker(g)
	case "collaborator":
		return runCollaborator(g)
	case "dashboard":
		return runDashboard(g)
	case "report":
		return runReport(g, rest)
	case "feedback":
		return runFeedback(rest)
	case "templates":
		return runTemplates(g)
	case "mcp":
		return mcp.NewServer(Version).Serve(os.Stdin, os.Stdout)
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", cmd)
		usage(fs)
		return 2
	}
}

// parseInterspersed lets global flags appear before or after the command and
// targets, not only before — so "report f.jsonl -o out.md" works like "-o out.md
// report f.jsonl". It repeatedly parses, peeling off one positional at a time.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positionals []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			break
		}
		positionals = append(positionals, rest[0])
		args = rest[1:]
	}
	return positionals, nil
}

func usage(fs *flag.FlagSet) {
	fmt.Fprint(os.Stderr, bigBanner())
	fmt.Fprintf(os.Stderr, "\nusage: huntx [global flags] <command> [targets...]\n\n")
	fmt.Fprintln(os.Stderr, "commands:")
	fmt.Fprintln(os.Stderr, "  scope check <target>   check whether targets fall in scope")
	fmt.Fprintln(os.Stderr, "  recon [domains...]     discover the attack surface")
	fmt.Fprintln(os.Stderr, "  scan [targets...]      run detection templates (+ --verify)")
	fmt.Fprintln(os.Stderr, "  run [domains...]       recon then scan")
	fmt.Fprintln(os.Stderr, "  full [domains...]      recon + crawl + scan + active param checks + plan")
	fmt.Fprintln(os.Stderr, "  monitor [domains...]   diff against last run; --interval to repeat")
	fmt.Fprintln(os.Stderr, "  api [targets...]       discover GraphQL/OpenAPI surface")
	fmt.Fprintln(os.Stderr, "  crawl [targets...]     mine endpoints/params from HTML and JS")
	fmt.Fprintln(os.Stderr, "  fuzz [targets...]      content discovery over a common-paths wordlist")
	fmt.Fprintln(os.Stderr, "  reflect <url>...       detect reflected parameters (potential XSS)")
	fmt.Fprintln(os.Stderr, "  redirect <url>...      detect open redirects in common params")
	fmt.Fprintln(os.Stderr, "  ssrf <url>...          OOB SSRF via a built-in collaborator (--base public URL)")
	fmt.Fprintln(os.Stderr, "  cmdi <url>...          OOB OS command injection (--base public URL)")
	fmt.Fprintln(os.Stderr, "  sqli <url>...          error-based SQL injection detection")
	fmt.Fprintln(os.Stderr, "  ssti <url>...          server-side template injection detection")
	fmt.Fprintln(os.Stderr, "  lfi <url>...           local file inclusion / path traversal detection")
	fmt.Fprintln(os.Stderr, "  hostheader <url>...    host-header injection detection")
	fmt.Fprintln(os.Stderr, "  bola <url>...          object-level authz test across identities (--identities)")
	fmt.Fprintln(os.Stderr, "  greybox --src <dir>    correlate source sinks with live endpoints")
	fmt.Fprintln(os.Stderr, "  plan [findings.jsonl]  rank findings by expected value, compose chains")
	fmt.Fprintln(os.Stderr, "  coordinate [targets...]  serve a scan queue for distributed workers")
	fmt.Fprintln(os.Stderr, "  worker --coordinator <url>  pull targets and scan them")
	fmt.Fprintln(os.Stderr, "  report <findings.jsonl>  render findings as markdown")
	fmt.Fprintln(os.Stderr, "  feedback accept|reject <template-id>...  train FP calibration")
	fmt.Fprintln(os.Stderr, "  templates              list/validate built-in and --templates dir")
	fmt.Fprintln(os.Stderr, "  dashboard              serve a local view of the graph and findings")
	fmt.Fprintln(os.Stderr, "  collaborator           run the OOB interaction server")
	fmt.Fprintln(os.Stderr, "  mcp                    serve huntx as an MCP server (stdio)")
	fmt.Fprintln(os.Stderr, "  version                print version")
	fmt.Fprintf(os.Stderr, "\nglobal flags:\n")
	fs.PrintDefaults()
}

func runScope(g *globalFlags, args []string) int {
	if len(args) == 0 || args[0] != "check" {
		fmt.Fprintln(os.Stderr, "usage: huntx --scope <file> scope check <target>...")
		return 2
	}
	if g.scopePath == "" {
		fmt.Fprintln(os.Stderr, "scope check needs --scope <file.json>")
		return 2
	}
	s, err := scope.Load(g.scopePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	targets := args[1:]
	if len(targets) == 0 {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			if t := strings.TrimSpace(sc.Text()); t != "" {
				printDecision(s, t)
			}
		}
	}
	for _, t := range targets {
		printDecision(s, t)
	}
	return 0
}

func printDecision(s *scope.Scope, target string) {
	d := s.Check(target)
	mark := "OUT"
	if d.Allowed {
		mark = "IN "
	}
	fmt.Printf("%s  %-40s  %s\n", mark, target, d.Reason)
}

func runRecon(cmd string, g *globalFlags, targets []string) int {
	s, err := authz.Config{Authorized: g.authorized, ScopePath: g.scopePath, DryRun: g.dryRun}.Verify()
	if err != nil {
		fmt.Fprintln(os.Stderr, "blocked:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	seeds := seedDomains(s, targets)
	if len(seeds) == 0 {
		fmt.Fprintln(os.Stderr, "no seed domains: pass a domain or add hosts to in_scope")
		return 1
	}
	fmt.Fprintln(os.Stderr, banner)
	fmt.Fprintf(os.Stderr, "recon | program=%q seeds=%s\n", s.Program, strings.Join(seeds, ","))

	results, gr := engine.Recon(ctx, seeds, g.opts(s))
	if err := gr.Save(graphFile); err != nil {
		fmt.Fprintln(os.Stderr, "graph save:", err)
	}
	writeResults(g.output, results)

	live := 0
	for _, r := range results {
		if r.Live {
			live++
		}
	}
	fmt.Fprintf(os.Stderr, "recon done: %d live of %d probed; graph -> %s\n", live, len(results), graphFile)

	if cmd == "run" {
		var targets []engine.Target
		for _, r := range results {
			if r.Live {
				base := r.URL
				if base == "" {
					base = "https://" + r.Host
				}
				targets = append(targets, engine.Target{Base: base, Techs: strings.Split(r.Tech, ",")})
			}
		}
		findings := engine.Scan(ctx, targets, g.opts(s))
		out := g.output
		if out == "" {
			out = findingsFile
		}
		writeFindings(out, findings)
		fmt.Fprintf(os.Stderr, "scan done: %d finding(s) -> %s\n", len(findings), out)
	}
	return 0
}

func seedDomains(s *scope.Scope, args []string) []string {
	src := args
	if len(src) == 0 {
		for _, r := range s.InScope {
			if !strings.Contains(r, "/") {
				src = append(src, r)
			}
		}
	}
	var out []string
	seen := map[string]struct{}{}
	for _, a := range src {
		a = strings.ToLower(strings.TrimSpace(a))
		a = strings.TrimPrefix(a, "*.")
		if a == "" {
			continue
		}
		if _, ok := seen[a]; ok {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	return out
}

func runScan(g *globalFlags, args []string) int {
	s, err := authz.Config{Authorized: g.authorized, ScopePath: g.scopePath, DryRun: g.dryRun}.Verify()
	if err != nil {
		fmt.Fprintln(os.Stderr, "blocked:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	targets := scanTargets(args)
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "no scan targets: run 'recon' first or pass hosts/URLs")
		return 1
	}
	fmt.Fprintln(os.Stderr, banner)
	fmt.Fprintf(os.Stderr, "scan | program=%q targets=%d verify=%v\n", s.Program, len(targets), g.verify)

	findings := filterSeverity(engine.Scan(ctx, targets, g.opts(s)), g.minSeverity)
	writeFindings(g.output, findings)
	fmt.Fprintf(os.Stderr, "scan done: %d finding(s)\n", len(findings))
	return 0
}

func scanTargets(args []string) []engine.Target {
	if len(args) > 0 {
		var out []engine.Target
		for _, a := range args {
			a = strings.TrimSpace(a)
			if !strings.Contains(a, "://") {
				a = "https://" + a
			}
			out = append(out, engine.Target{Base: a})
		}
		return out
	}
	gr, err := graph.Load(graphFile)
	if err != nil {
		return nil
	}
	var out []engine.Target
	for _, n := range gr.Nodes {
		if n.Kind != graph.Subdomain {
			continue
		}
		if _, live := n.Attrs["status"]; !live {
			continue
		}
		base := n.Attrs["url"]
		if base == "" {
			base = "https://" + n.Value
		}
		var techs []string
		if n.Attrs["tech"] != "" {
			techs = strings.Split(n.Attrs["tech"], ",")
		}
		out = append(out, engine.Target{Base: base, Techs: techs})
	}
	return out
}

func runReport(g *globalFlags, args []string) int {
	var r *bufio.Scanner
	if len(args) > 0 {
		f, err := os.Open(args[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, "report:", err)
			return 1
		}
		defer f.Close()
		r = bufio.NewScanner(f)
	} else {
		r = bufio.NewScanner(os.Stdin)
	}
	r.Buffer(make([]byte, 1<<20), 16<<20)

	var findings []finding.Finding
	for r.Scan() {
		line := strings.TrimSpace(r.Text())
		if line == "" {
			continue
		}
		var f finding.Finding
		if err := json.Unmarshal([]byte(line), &f); err == nil {
			findings = append(findings, f)
		}
	}

	findings = filterSeverity(findings, g.minSeverity)
	if strings.HasSuffix(g.output, ".sarif") {
		b, err := sarif.Build(Version, findings)
		if err != nil {
			fmt.Fprintln(os.Stderr, "sarif:", err)
			return 1
		}
		if err := os.WriteFile(g.output, b, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "report:", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "sarif -> %s (%d finding(s))\n", g.output, len(findings))
		return 0
	}

	program := ""
	if g.scopePath != "" {
		if s, err := scope.Load(g.scopePath); err == nil {
			program = s.Program
		}
	}
	md := report.Markdown(program, findings)
	if g.output != "" {
		if err := os.WriteFile(g.output, []byte(md), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "report:", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "report -> %s (%d finding(s))\n", g.output, len(findings))
		return 0
	}
	fmt.Print(md)
	return 0
}

func runMonitor(g *globalFlags, args []string) int {
	s, err := authz.Config{Authorized: g.authorized, ScopePath: g.scopePath, DryRun: g.dryRun}.Verify()
	if err != nil {
		fmt.Fprintln(os.Stderr, "blocked:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	seeds := seedDomains(s, args)
	if len(seeds) == 0 {
		fmt.Fprintln(os.Stderr, "no seed domains: pass a domain or add hosts to in_scope")
		return 1
	}

	var interval time.Duration
	if g.interval != "" {
		d, err := time.ParseDuration(g.interval)
		if err != nil {
			fmt.Fprintln(os.Stderr, "bad --interval:", err)
			return 2
		}
		interval = d
	}

	fmt.Fprintln(os.Stderr, banner)
	fmt.Fprintf(os.Stderr, "monitor | program=%q seeds=%s interval=%s\n", s.Program, strings.Join(seeds, ","), g.interval)

	monitorPass(ctx, g, s, seeds)
	if interval <= 0 {
		return 0
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return 0
		case <-t.C:
			monitorPass(ctx, g, s, seeds)
		}
	}
}

func monitorPass(ctx context.Context, g *globalFlags, s *scope.Scope, seeds []string) {
	old, err := graph.Load(graphFile)
	first := err != nil
	if first {
		old = graph.New()
	}

	results, gr := engine.Recon(ctx, seeds, g.opts(s))
	newHosts := monitor.NewHosts(old, gr)
	if err := gr.Save(graphFile); err != nil {
		fmt.Fprintln(os.Stderr, "graph save:", err)
	}

	var targets []engine.Target
	if first {
		targets = targetsFromResults(results)
	} else {
		targets = targetsFromNodes(newHosts)
	}

	findings := engine.Scan(ctx, targets, g.opts(s))
	prev := loadFindings(findingsFile)
	fresh := monitor.NewFindings(prev, findings)
	writeFindings(findingsFile, monitor.Merge(prev, findings))

	stamp := time.Now().Format("15:04:05")
	fmt.Fprintf(os.Stderr, "[%s] new hosts: %d, new findings: %d\n", stamp, len(newHosts), len(fresh))
	for _, n := range newHosts {
		fmt.Printf("+ host %s\n", n.Value)
	}
	for _, f := range fresh {
		fmt.Printf("+ finding [%s] %s %s\n", f.Severity, f.TemplateID, f.MatchedAt)
	}

	if g.notify != "" && (len(newHosts) > 0 || len(fresh) > 0) {
		msg := fmt.Sprintf("huntx %s: %d new host(s), %d new finding(s)", s.Program, len(newHosts), len(fresh))
		for _, f := range fresh {
			msg += fmt.Sprintf("\n- [%s] %s %s", f.Severity, f.TemplateID, f.MatchedAt)
		}
		if err := notify.Send(ctx, g.notify, msg); err != nil {
			fmt.Fprintln(os.Stderr, "notify:", err)
		}
	}
}

func targetsFromResults(results []recon.Result) []engine.Target {
	var out []engine.Target
	for _, r := range results {
		if !r.Live {
			continue
		}
		base := r.URL
		if base == "" {
			base = "https://" + r.Host
		}
		out = append(out, engine.Target{Base: base, Techs: strings.Split(r.Tech, ",")})
	}
	return out
}

func targetsFromNodes(nodes []*graph.Node) []engine.Target {
	var out []engine.Target
	for _, n := range nodes {
		if _, live := n.Attrs["status"]; !live {
			continue
		}
		base := n.Attrs["url"]
		if base == "" {
			base = "https://" + n.Value
		}
		var techs []string
		if n.Attrs["tech"] != "" {
			techs = strings.Split(n.Attrs["tech"], ",")
		}
		out = append(out, engine.Target{Base: base, Techs: techs})
	}
	return out
}

func loadFindings(path string) []finding.Finding {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	var out []finding.Finding
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var x finding.Finding
		if json.Unmarshal([]byte(line), &x) == nil {
			out = append(out, x)
		}
	}
	return out
}

func runApi(g *globalFlags, args []string) int {
	s, err := authz.Config{Authorized: g.authorized, ScopePath: g.scopePath, DryRun: g.dryRun}.Verify()
	if err != nil {
		fmt.Fprintln(os.Stderr, "blocked:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	targets := scanTargets(args)
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "no targets: run 'recon' first or pass hosts/URLs")
		return 1
	}
	client := g.opts(s).Client()
	gr, err := graph.Load(graphFile)
	if err != nil {
		gr = graph.New()
	}

	fmt.Fprintln(os.Stderr, banner)
	fmt.Fprintf(os.Stderr, "api | program=%q targets=%d\n", s.Program, len(targets))

	var all []finding.Finding
	endpoints := 0
	for _, t := range targets {
		if !s.Check(t.Base).Allowed {
			continue
		}
		fs, eps := apidisco.Discover(ctx, client, t.Base)
		all = append(all, fs...)
		host := strings.TrimPrefix(strings.TrimPrefix(t.Base, "https://"), "http://")
		if i := strings.IndexByte(host, '/'); i >= 0 {
			host = host[:i]
		}
		hostNode := gr.Upsert(graph.Subdomain, host, nil)
		for _, e := range eps {
			ep := gr.Upsert(graph.Endpoint, e.Method+" "+strings.TrimRight(t.Base, "/")+e.Path, map[string]string{"method": e.Method})
			gr.Link(hostNode, ep, "has_endpoint")
			endpoints++
		}
		if ctx.Err() != nil {
			break
		}
	}
	if err := gr.Save(graphFile); err != nil {
		fmt.Fprintln(os.Stderr, "graph save:", err)
	}
	writeFindings(g.output, all)
	fmt.Fprintf(os.Stderr, "api done: %d finding(s), %d endpoint(s) added to graph\n", len(all), endpoints)
	return 0
}

func runFuzz(g *globalFlags, args []string) int {
	s, err := authz.Config{Authorized: g.authorized, ScopePath: g.scopePath, DryRun: g.dryRun}.Verify()
	if err != nil {
		fmt.Fprintln(os.Stderr, "blocked:", err)
		return 1
	}
	targets := scanTargets(args)
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "no targets: run 'recon' first or pass hosts/URLs")
		return 1
	}
	words, err := fuzz.Words(g.wordlist)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wordlist:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	client := g.opts(s).Client()
	gr, err := graph.Load(graphFile)
	if err != nil {
		gr = graph.New()
	}

	fmt.Fprintln(os.Stderr, banner)
	fmt.Fprintf(os.Stderr, "fuzz | program=%q targets=%d words=%d\n", s.Program, len(targets), len(words))

	total := 0
	for _, t := range targets {
		if !s.Check(t.Base).Allowed {
			continue
		}
		host := strings.TrimPrefix(strings.TrimPrefix(t.Base, "https://"), "http://")
		if i := strings.IndexByte(host, '/'); i >= 0 {
			host = host[:i]
		}
		hostNode := gr.Upsert(graph.Subdomain, host, nil)
		for _, h := range fuzz.Run(ctx, client, t.Base, words, g.concurrency) {
			fmt.Printf("%-4d %s\n", h.Status, h.URL)
			n := gr.Upsert(graph.Endpoint, "GET "+h.URL, map[string]string{"status": strconv.Itoa(h.Status)})
			gr.Link(hostNode, n, "has_endpoint")
			total++
		}
		if ctx.Err() != nil {
			break
		}
	}
	if err := gr.Save(graphFile); err != nil {
		fmt.Fprintln(os.Stderr, "graph save:", err)
	}
	fmt.Fprintf(os.Stderr, "fuzz done: %d path(s) found, added to graph\n", total)
	return 0
}

func runCrawl(g *globalFlags, args []string) int {
	s, err := authz.Config{Authorized: g.authorized, ScopePath: g.scopePath, DryRun: g.dryRun}.Verify()
	if err != nil {
		fmt.Fprintln(os.Stderr, "blocked:", err)
		return 1
	}
	targets := scanTargets(args)
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "no targets: run 'recon' first or pass hosts/URLs")
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	client := g.opts(s).Client()
	gr, err := graph.Load(graphFile)
	if err != nil {
		gr = graph.New()
	}

	fmt.Fprintln(os.Stderr, banner)
	fmt.Fprintf(os.Stderr, "crawl | program=%q targets=%d\n", s.Program, len(targets))

	endpoints, params := 0, 0
	for _, t := range targets {
		if !s.Check(t.Base).Allowed {
			continue
		}
		host := strings.TrimPrefix(strings.TrimPrefix(t.Base, "https://"), "http://")
		if i := strings.IndexByte(host, '/'); i >= 0 {
			host = host[:i]
		}
		hostNode := gr.Upsert(graph.Subdomain, host, nil)
		res := crawl.Run(ctx, client, t.Base)
		for _, ep := range res.Endpoints {
			n := gr.Upsert(graph.Endpoint, strings.TrimRight(t.Base, "/")+ep, nil)
			gr.Link(hostNode, n, "has_endpoint")
			endpoints++
		}
		for _, p := range res.Params {
			n := gr.Upsert(graph.Param, host+"::"+p, map[string]string{"name": p})
			gr.Link(hostNode, n, "has_param")
			params++
		}
		if ctx.Err() != nil {
			break
		}
	}
	if err := gr.Save(graphFile); err != nil {
		fmt.Fprintln(os.Stderr, "graph save:", err)
	}
	fmt.Fprintf(os.Stderr, "crawl done: %d endpoint(s), %d param(s) added to graph\n", endpoints, params)
	return 0
}

func runReflect(g *globalFlags, args []string) int {
	s, err := authz.Config{Authorized: g.authorized, ScopePath: g.scopePath, DryRun: g.dryRun}.Verify()
	if err != nil {
		fmt.Fprintln(os.Stderr, "blocked:", err)
		return 1
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "reflect needs at least one URL")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	client := g.opts(s).Client()
	paramsByHost := graphParams()

	fmt.Fprintln(os.Stderr, banner)
	fmt.Fprintf(os.Stderr, "reflect | urls=%d\n", len(args))

	var out []finding.Finding
	for _, u := range args {
		if !strings.Contains(u, "://") {
			u = "https://" + u
		}
		if !s.Check(u).Allowed {
			fmt.Fprintf(os.Stderr, "skip out-of-scope: %s\n", u)
			continue
		}
		host := strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
		if i := strings.IndexByte(host, '/'); i >= 0 {
			host = host[:i]
		}
		out = append(out, reflectx.Test(ctx, client, u, paramsByHost[host])...)
		if ctx.Err() != nil {
			break
		}
	}
	writeFindings(g.output, out)
	fmt.Fprintf(os.Stderr, "reflect done: %d finding(s)\n", len(out))
	return 0
}

func runSSRF(g *globalFlags, args []string) int {
	s, err := authz.Config{Authorized: g.authorized, ScopePath: g.scopePath, DryRun: g.dryRun}.Verify()
	if err != nil {
		fmt.Fprintln(os.Stderr, "blocked:", err)
		return 1
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "ssrf needs at least one URL")
		return 2
	}
	base := g.base
	if base == "" {
		base = "http://localhost" + g.listen
	}
	collab := collaborator.NewServer(base)
	srv := &http.Server{Addr: g.listen, Handler: collab.Handler()}
	go srv.ListenAndServe()
	defer srv.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	client := g.opts(s).Client()
	paramsByHost := graphParams()

	fmt.Fprintln(os.Stderr, banner)
	fmt.Fprintf(os.Stderr, "ssrf | collaborator base=%s urls=%d\n", base, len(args))
	fmt.Fprintln(os.Stderr, "note: --base must be reachable by the target for OOB callbacks to arrive")

	var out []finding.Finding
	for _, u := range args {
		if !strings.Contains(u, "://") {
			u = "https://" + u
		}
		if !s.Check(u).Allowed {
			fmt.Fprintf(os.Stderr, "skip out-of-scope: %s\n", u)
			continue
		}
		out = append(out, ssrf.Test(ctx, client, collab, u, paramsByHost[hostOfURL(u)], 5*time.Second)...)
		if ctx.Err() != nil {
			break
		}
	}
	writeFindings(g.output, out)
	fmt.Fprintf(os.Stderr, "ssrf done: %d finding(s)\n", len(out))
	return 0
}

func runFull(g *globalFlags, args []string) int {
	s, err := authz.Config{Authorized: g.authorized, ScopePath: g.scopePath, DryRun: g.dryRun}.Verify()
	if err != nil {
		fmt.Fprintln(os.Stderr, "blocked:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	seeds := seedDomains(s, args)
	if len(seeds) == 0 {
		fmt.Fprintln(os.Stderr, "no seed domains: pass a domain or add hosts to in_scope")
		return 1
	}
	fmt.Fprintln(os.Stderr, banner)
	fmt.Fprintf(os.Stderr, "full | program=%q seeds=%s\n", s.Program, strings.Join(seeds, ","))

	results, gr := engine.Recon(ctx, seeds, g.opts(s))
	live := targetsFromResults(results)
	fmt.Fprintf(os.Stderr, "recon: %d live host(s)\n", len(live))

	client := g.opts(s).Client()
	for _, t := range live {
		host := hostOfURL(t.Base)
		hostNode := gr.Upsert(graph.Subdomain, host, nil)
		res := crawl.Run(ctx, client, t.Base)
		for _, ep := range res.Endpoints {
			gr.Link(hostNode, gr.Upsert(graph.Endpoint, strings.TrimRight(t.Base, "/")+ep, nil), "has_endpoint")
		}
		for _, p := range res.Params {
			gr.Link(hostNode, gr.Upsert(graph.Param, host+"::"+p, map[string]string{"name": p}), "has_param")
		}
		if ctx.Err() != nil {
			break
		}
	}
	_ = gr.Save(graphFile)
	paramsByHost := graphParamsFrom(gr)

	seen := map[string]bool{}
	var findings []finding.Finding
	add := func(fs []finding.Finding) {
		for _, f := range fs {
			if seen[f.DedupKey] {
				continue
			}
			seen[f.DedupKey] = true
			findings = append(findings, f)
		}
	}

	add(engine.Scan(ctx, live, g.opts(s)))
	for _, t := range live {
		if ctx.Err() != nil {
			break
		}
		ps := paramsByHost[hostOfURL(t.Base)]
		add(reflectx.Test(ctx, client, t.Base, ps))
		add(sqli.Test(ctx, client, t.Base, ps))
		add(ssti.Test(ctx, client, t.Base, ps))
		add(openredirect.Test(ctx, client, t.Base, ps))
		add(lfi.Test(ctx, client, t.Base, ps))
		add(hostheader.Test(ctx, client, t.Base))
	}

	findings = filterSeverity(findings, g.minSeverity)
	out := g.output
	if out == "" {
		out = findingsFile
	}
	writeFindings(out, findings)
	fmt.Fprintf(os.Stderr, "full done: %d finding(s) -> %s\n", len(findings), out)

	if len(findings) > 0 {
		fmt.Fprintln(os.Stderr, "\nplaybook:")
		for _, a := range agent.Plan(findings) {
			tag := " "
			if a.Chain {
				tag = "⛓"
			}
			fmt.Printf("%s %.2f  [%-8s] %s\n", tag, a.EV, a.Severity, a.Title)
		}
	}
	return 0
}

func runHostHeader(g *globalFlags, args []string) int {
	s, err := authz.Config{Authorized: g.authorized, ScopePath: g.scopePath, DryRun: g.dryRun}.Verify()
	if err != nil {
		fmt.Fprintln(os.Stderr, "blocked:", err)
		return 1
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "hostheader needs at least one URL")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	client := g.opts(s).Client()

	fmt.Fprintln(os.Stderr, banner)
	fmt.Fprintf(os.Stderr, "hostheader | urls=%d\n", len(args))

	var out []finding.Finding
	for _, u := range args {
		if !strings.Contains(u, "://") {
			u = "https://" + u
		}
		if !s.Check(u).Allowed {
			fmt.Fprintf(os.Stderr, "skip out-of-scope: %s\n", u)
			continue
		}
		out = append(out, hostheader.Test(ctx, client, u)...)
		if ctx.Err() != nil {
			break
		}
	}
	writeFindings(g.output, out)
	fmt.Fprintf(os.Stderr, "hostheader done: %d finding(s)\n", len(out))
	return 0
}

func runLFI(g *globalFlags, args []string) int {
	s, err := authz.Config{Authorized: g.authorized, ScopePath: g.scopePath, DryRun: g.dryRun}.Verify()
	if err != nil {
		fmt.Fprintln(os.Stderr, "blocked:", err)
		return 1
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "lfi needs at least one URL")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	client := g.opts(s).Client()
	paramsByHost := graphParams()

	fmt.Fprintln(os.Stderr, banner)
	fmt.Fprintf(os.Stderr, "lfi | urls=%d\n", len(args))

	var out []finding.Finding
	for _, u := range args {
		if !strings.Contains(u, "://") {
			u = "https://" + u
		}
		if !s.Check(u).Allowed {
			fmt.Fprintf(os.Stderr, "skip out-of-scope: %s\n", u)
			continue
		}
		out = append(out, lfi.Test(ctx, client, u, paramsByHost[hostOfURL(u)])...)
		if ctx.Err() != nil {
			break
		}
	}
	writeFindings(g.output, out)
	fmt.Fprintf(os.Stderr, "lfi done: %d finding(s)\n", len(out))
	return 0
}

func runSSTI(g *globalFlags, args []string) int {
	s, err := authz.Config{Authorized: g.authorized, ScopePath: g.scopePath, DryRun: g.dryRun}.Verify()
	if err != nil {
		fmt.Fprintln(os.Stderr, "blocked:", err)
		return 1
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "ssti needs at least one URL")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	client := g.opts(s).Client()
	paramsByHost := graphParams()

	fmt.Fprintln(os.Stderr, banner)
	fmt.Fprintf(os.Stderr, "ssti | urls=%d\n", len(args))

	var out []finding.Finding
	for _, u := range args {
		if !strings.Contains(u, "://") {
			u = "https://" + u
		}
		if !s.Check(u).Allowed {
			fmt.Fprintf(os.Stderr, "skip out-of-scope: %s\n", u)
			continue
		}
		out = append(out, ssti.Test(ctx, client, u, paramsByHost[hostOfURL(u)])...)
		if ctx.Err() != nil {
			break
		}
	}
	writeFindings(g.output, out)
	fmt.Fprintf(os.Stderr, "ssti done: %d finding(s)\n", len(out))
	return 0
}

func runSQLi(g *globalFlags, args []string) int {
	s, err := authz.Config{Authorized: g.authorized, ScopePath: g.scopePath, DryRun: g.dryRun}.Verify()
	if err != nil {
		fmt.Fprintln(os.Stderr, "blocked:", err)
		return 1
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "sqli needs at least one URL")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	client := g.opts(s).Client()
	paramsByHost := graphParams()

	fmt.Fprintln(os.Stderr, banner)
	fmt.Fprintf(os.Stderr, "sqli | urls=%d\n", len(args))

	var out []finding.Finding
	for _, u := range args {
		if !strings.Contains(u, "://") {
			u = "https://" + u
		}
		if !s.Check(u).Allowed {
			fmt.Fprintf(os.Stderr, "skip out-of-scope: %s\n", u)
			continue
		}
		out = append(out, sqli.Test(ctx, client, u, paramsByHost[hostOfURL(u)])...)
		if ctx.Err() != nil {
			break
		}
	}
	writeFindings(g.output, out)
	fmt.Fprintf(os.Stderr, "sqli done: %d finding(s)\n", len(out))
	return 0
}

func runCmdi(g *globalFlags, args []string) int {
	s, err := authz.Config{Authorized: g.authorized, ScopePath: g.scopePath, DryRun: g.dryRun}.Verify()
	if err != nil {
		fmt.Fprintln(os.Stderr, "blocked:", err)
		return 1
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "cmdi needs at least one URL")
		return 2
	}
	base := g.base
	if base == "" {
		base = "http://localhost" + g.listen
	}
	collab := collaborator.NewServer(base)
	srv := &http.Server{Addr: g.listen, Handler: collab.Handler()}
	go srv.ListenAndServe()
	defer srv.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	client := g.opts(s).Client()
	paramsByHost := graphParams()

	fmt.Fprintln(os.Stderr, banner)
	fmt.Fprintf(os.Stderr, "cmdi | collaborator base=%s urls=%d\n", base, len(args))
	fmt.Fprintln(os.Stderr, "note: --base must be reachable by the target for OOB callbacks to arrive")

	var out []finding.Finding
	for _, u := range args {
		if !strings.Contains(u, "://") {
			u = "https://" + u
		}
		if !s.Check(u).Allowed {
			fmt.Fprintf(os.Stderr, "skip out-of-scope: %s\n", u)
			continue
		}
		out = append(out, cmdi.Test(ctx, client, collab, u, paramsByHost[hostOfURL(u)], 5*time.Second)...)
		if ctx.Err() != nil {
			break
		}
	}
	writeFindings(g.output, out)
	fmt.Fprintf(os.Stderr, "cmdi done: %d finding(s)\n", len(out))
	return 0
}

func runRedirect(g *globalFlags, args []string) int {
	s, err := authz.Config{Authorized: g.authorized, ScopePath: g.scopePath, DryRun: g.dryRun}.Verify()
	if err != nil {
		fmt.Fprintln(os.Stderr, "blocked:", err)
		return 1
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "redirect needs at least one URL")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	client := g.opts(s).Client()
	paramsByHost := graphParams()

	fmt.Fprintln(os.Stderr, banner)
	fmt.Fprintf(os.Stderr, "redirect | urls=%d\n", len(args))

	var out []finding.Finding
	for _, u := range args {
		if !strings.Contains(u, "://") {
			u = "https://" + u
		}
		if !s.Check(u).Allowed {
			fmt.Fprintf(os.Stderr, "skip out-of-scope: %s\n", u)
			continue
		}
		host := hostOfURL(u)
		out = append(out, openredirect.Test(ctx, client, u, paramsByHost[host])...)
		if ctx.Err() != nil {
			break
		}
	}
	writeFindings(g.output, out)
	fmt.Fprintf(os.Stderr, "redirect done: %d finding(s)\n", len(out))
	return 0
}

func hostOfURL(u string) string {
	h := strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	if i := strings.IndexByte(h, '/'); i >= 0 {
		h = h[:i]
	}
	return h
}

// graphParams collects parameter names discovered per host (by crawl) from the graph.
func graphParams() map[string][]string {
	gr, err := graph.Load(graphFile)
	if err != nil {
		return map[string][]string{}
	}
	return graphParamsFrom(gr)
}

func graphParamsFrom(gr *graph.Graph) map[string][]string {
	out := map[string][]string{}
	for _, n := range gr.Nodes {
		if n.Kind != graph.Param {
			continue
		}
		host, name := n.Value, ""
		if i := strings.Index(n.Value, "::"); i >= 0 {
			host, name = n.Value[:i], n.Value[i+2:]
		}
		if name != "" {
			out[host] = append(out[host], name)
		}
	}
	return out
}

func runBola(g *globalFlags, args []string) int {
	s, err := authz.Config{Authorized: g.authorized, ScopePath: g.scopePath, DryRun: g.dryRun}.Verify()
	if err != nil {
		fmt.Fprintln(os.Stderr, "blocked:", err)
		return 1
	}
	if g.identities == "" {
		fmt.Fprintln(os.Stderr, "bola needs --identities <file.json>")
		return 2
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "bola needs at least one URL to test")
		return 2
	}
	ids, err := session.Load(g.identities)
	if err != nil {
		fmt.Fprintln(os.Stderr, "identities:", err)
		return 1
	}
	ownerID, ok := ids[g.owner]
	if !ok {
		fmt.Fprintf(os.Stderr, "owner identity %q not found in %s\n", g.owner, g.identities)
		return 1
	}
	owner := verify.Creds{Label: g.owner, Headers: ownerID.Headers}
	var others []verify.Creds
	for name, id := range ids {
		if name != g.owner {
			others = append(others, verify.Creds{Label: name, Headers: id.Headers})
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	client := g.opts(s).Client()

	fmt.Fprintln(os.Stderr, banner)
	fmt.Fprintf(os.Stderr, "bola | owner=%s others=%d urls=%d\n", g.owner, len(others), len(args))

	var out []finding.Finding
	for _, u := range args {
		if !strings.Contains(u, "://") {
			u = "https://" + u
		}
		if !s.Check(u).Allowed {
			fmt.Fprintf(os.Stderr, "skip out-of-scope: %s\n", u)
			continue
		}
		if f, ok := verify.Differential(ctx, client, u, owner, others...); ok {
			out = append(out, f)
		}
		if ctx.Err() != nil {
			break
		}
	}
	writeFindings(g.output, out)
	fmt.Fprintf(os.Stderr, "bola done: %d finding(s)\n", len(out))
	return 0
}

func runPlan(g *globalFlags, args []string) int {
	path := findingsFile
	if len(args) > 0 {
		path = args[0]
	}
	findings := loadFindings(path)
	if len(findings) == 0 {
		fmt.Fprintf(os.Stderr, "no findings in %s (run scan -o %s first)\n", path, findingsFile)
		return 1
	}
	actions := agent.Plan(findings)
	for _, a := range actions {
		tag := " "
		if a.Chain {
			tag = "⛓"
		}
		fmt.Printf("%s %.2f  [%-8s] %s\n     %s\n", tag, a.EV, a.Severity, a.Title, a.Rationale)
	}
	return 0
}

func runGreybox(g *globalFlags) int {
	if g.src == "" {
		fmt.Fprintln(os.Stderr, "greybox needs --src <dir>")
		return 2
	}
	reports, err := greybox.ScanTree(g.src)
	if err != nil {
		fmt.Fprintln(os.Stderr, "greybox:", err)
		return 1
	}
	var endpoints []string
	if gr, err := graph.Load(graphFile); err == nil {
		for _, n := range gr.Nodes {
			if n.Kind == graph.Endpoint {
				v := n.Value
				if i := strings.IndexByte(v, ' '); i >= 0 {
					v = v[i+1:]
				}
				endpoints = append(endpoints, v)
			}
		}
	}

	sinks := 0
	for _, r := range reports {
		sinks += len(r.Sinks)
	}
	findings := greybox.Correlate(reports, endpoints)

	fmt.Fprintln(os.Stderr, banner)
	fmt.Fprintf(os.Stderr, "greybox | files-with-sinks=%d sinks=%d endpoints=%d correlated=%d\n",
		len(reports), sinks, len(endpoints), len(findings))
	writeFindings(g.output, findings)
	if len(endpoints) == 0 {
		fmt.Fprintln(os.Stderr, "note: no endpoints in graph — run 'recon'/'api' first for correlation")
	}
	return 0
}

func runTemplates(g *globalFlags) int {
	tpls, err := template.Builtin()
	if err != nil {
		fmt.Fprintln(os.Stderr, "builtin templates:", err)
		return 1
	}
	builtin := len(tpls)
	bad := 0
	if g.templatesDir != "" {
		extra, err := template.LoadDir(g.templatesDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "validation:", err)
			bad = 1
		}
		tpls = append(tpls, extra...)
	}
	for _, t := range tpls {
		sev := t.Info.Severity
		if sev == "" {
			sev = "info"
		}
		fmt.Printf("%-26s [%-8s] %s\n", t.ID, sev, t.Info.Tags)
	}
	fmt.Fprintf(os.Stderr, "%d template(s) (%d built-in)\n", len(tpls), builtin)
	if bad > 0 {
		return 1
	}
	return 0
}

func runFeedback(args []string) int {
	if len(args) < 2 || (args[0] != "accept" && args[0] != "reject") {
		fmt.Fprintln(os.Stderr, "usage: huntx feedback accept|reject <template-id>...")
		return 2
	}
	accepted := args[0] == "accept"
	store := feedback.Load(feedbackFile)
	for _, id := range args[1:] {
		store.Record(id, accepted)
	}
	if err := store.Save(); err != nil {
		fmt.Fprintln(os.Stderr, "feedback:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "recorded %s for %d template(s) -> %s\n", args[0], len(args)-1, feedbackFile)
	return 0
}

func runCoordinate(g *globalFlags, args []string) int {
	s, err := authz.Config{Authorized: g.authorized, ScopePath: g.scopePath, DryRun: g.dryRun}.Verify()
	if err != nil {
		fmt.Fprintln(os.Stderr, "blocked:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var bases []string
	for _, t := range scanTargets(args) {
		if s.Check(t.Base).Allowed {
			bases = append(bases, t.Base)
		}
	}
	if len(bases) == 0 {
		fmt.Fprintln(os.Stderr, "no in-scope targets: run 'recon' first or pass hosts/URLs")
		return 1
	}

	c := distributed.NewCoordinator(bases)
	srv := &http.Server{Addr: g.listen, Handler: c.Handler()}
	go srv.ListenAndServe()

	fmt.Fprintln(os.Stderr, banner)
	fmt.Fprintf(os.Stderr, "coordinator on http://localhost%s | %d target(s) queued\n", g.listen, len(bases))

	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for !c.Complete() {
		select {
		case <-ctx.Done():
			_ = srv.Close()
			return 0
		case <-t.C:
		}
	}
	shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutCtx)

	out := g.output
	if out == "" {
		out = findingsFile
	}
	writeFindings(out, c.Results())
	fmt.Fprintf(os.Stderr, "coordinate done: %d finding(s) -> %s\n", len(c.Results()), out)
	return 0
}

func runWorker(g *globalFlags) int {
	s, err := authz.Config{Authorized: g.authorized, ScopePath: g.scopePath, DryRun: g.dryRun}.Verify()
	if err != nil {
		fmt.Fprintln(os.Stderr, "blocked:", err)
		return 1
	}
	if g.coordinator == "" {
		fmt.Fprintln(os.Stderr, "worker needs --coordinator <url>")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	scanOne := func(base string) []finding.Finding {
		return engine.Scan(ctx, []engine.Target{{Base: base}}, g.opts(s))
	}
	fmt.Fprintln(os.Stderr, banner)
	fmt.Fprintf(os.Stderr, "worker | coordinator=%s\n", g.coordinator)
	if err := distributed.Work(ctx, g.coordinator, scanOne); err != nil {
		fmt.Fprintln(os.Stderr, "worker:", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "worker done: queue drained")
	return 0
}

func runDashboard(g *globalFlags) int {
	addr := g.listen
	if addr == ":8888" {
		addr = ":8899"
	}
	fmt.Fprintln(os.Stderr, banner)
	fmt.Fprintf(os.Stderr, "dashboard on http://localhost%s\n", addr)
	if err := (&http.Server{Addr: addr, Handler: dashboard.Handler(graphFile, findingsFile)}).ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, "dashboard:", err)
		return 1
	}
	return 0
}

func runCollaborator(g *globalFlags) int {
	base := g.base
	if base == "" {
		base = "http://localhost" + g.listen
	}
	s := collaborator.NewServer(base)
	fmt.Fprintln(os.Stderr, banner)
	fmt.Fprintf(os.Stderr, "collaborator listening on %s (base %s)\n", g.listen, base)
	if err := (&http.Server{Addr: g.listen, Handler: s.Handler()}).ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, "collaborator:", err)
		return 1
	}
	return 0
}

func writeResults(path string, results []recon.Result) {
	if path != "" {
		f, err := os.Create(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, "output:", err)
			return
		}
		defer f.Close()
		enc := json.NewEncoder(f)
		for _, r := range results {
			if r.Live {
				_ = enc.Encode(r)
			}
		}
		return
	}
	for _, r := range results {
		if r.Live {
			fmt.Printf("%-4d %-45s %s\n", r.Status, r.Host, strings.TrimSpace(r.Server+" "+r.Tech))
		}
	}
}

func filterSeverity(findings []finding.Finding, min string) []finding.Finding {
	if min == "" {
		return findings
	}
	threshold := finding.Severity(strings.ToLower(strings.TrimSpace(min))).Rank()
	kept := make([]finding.Finding, 0, len(findings))
	for _, f := range findings {
		if f.Severity.Rank() >= threshold {
			kept = append(kept, f)
		}
	}
	return kept
}

func writeFindings(path string, results []finding.Finding) {
	if path != "" {
		f, err := os.Create(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, "output:", err)
			return
		}
		defer f.Close()
		enc := json.NewEncoder(f)
		for _, r := range results {
			_ = enc.Encode(r)
		}
		return
	}
	for _, r := range results {
		sev := string(r.Severity)
		if sev == "" {
			sev = "info"
		}
		mark := " "
		if r.Verified {
			mark = "✓"
		}
		fmt.Printf("%s [%-8s] %-24s %s\n", mark, sev, r.TemplateID, r.MatchedAt)
	}
}
