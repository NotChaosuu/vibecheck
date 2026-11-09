package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/NotChaosuu/vibecheck/internal/model"
	"github.com/NotChaosuu/vibecheck/internal/report"
	"github.com/NotChaosuu/vibecheck/internal/rules"
	"github.com/NotChaosuu/vibecheck/internal/scan"
	"github.com/NotChaosuu/vibecheck/internal/score"
)

const version = "0.1.1"

func main() {
	fs := flag.NewFlagSet("vibecheck", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "emit JSON instead of the pretty report")
	verbose := fs.Bool("v", false, "verbose: show OWASP category and full explanation per finding")
	minSev := fs.String("min-severity", "", "only show findings at or above this severity (critical/high/medium/low)")
	confirmedOnly := fs.Bool("confirmed-only", false, "hide REVIEW findings, show only confirmed ones")
	frontendOnly := fs.Bool("frontend-only", false, "scan only frontend code")
	backendOnly := fs.Bool("backend-only", false, "scan only backend code")
	noSCA := fs.Bool("no-sca", false, "skip the dependency (supply-chain) check")
	offline := fs.Bool("offline", false, "never hit the network (implies --no-sca for OSV queries)")
	timeout := fs.Int("timeout", 25, "network timeout in seconds for dependency checks")
	exitCode := fs.Bool("exit-code", false, "exit non-zero if any confirmed critical/high issue is found (for CI)")
	list := fs.Bool("list", false, "list the rule catalogue and exit")
	showVersion := fs.Bool("version", false, "print version and exit")
	fs.Usage = usage
	_ = fs.Parse(os.Args[1:])

	if *showVersion {
		fmt.Printf("vibecheck %s (%d rules)\n", version, rules.Count()+specialRuleCount)
		return
	}
	if *list {
		listRules()
		return
	}

	target := "."
	if fs.NArg() > 0 {
		target = fs.Arg(0)
	}
	if st, err := os.Stat(target); err != nil || !st.IsDir() {
		fmt.Fprintf(os.Stderr, "error: %q is not a directory\n", target)
		os.Exit(2)
	}

	quiet := *asJSON
	status := func(msg string) {
		if !quiet {
			fmt.Fprint(os.Stderr, msg)
		}
	}

	status(fmt.Sprintf("scanning %s ...\n", target))
	result, scaErr := scan.Run(scan.Options{
		Target:       target,
		FrontendOnly: *frontendOnly,
		BackendOnly:  *backendOnly,
		NoSCA:        *noSCA,
		Offline:      *offline,
		Timeout:      time.Duration(*timeout) * time.Second,
		Status:       status,
	})
	if result == nil {
		fmt.Fprintf(os.Stderr, "error scanning %s: %v\n", target, scaErr)
		os.Exit(1)
	}
	if scaErr != nil {
		status(fmt.Sprintf("  (dependency check skipped: %v)\n", scaErr))
	}

	result.Findings = filterFindings(result.Findings, *minSev, *confirmedOnly)
	result.VulnDeps = filterVulnDeps(result.VulnDeps, *minSev)
	result.Score, result.Grade, result.Counts = score.Compute(result.Findings, result.VulnDeps)
	report.Sort(result)

	if *asJSON {
		_ = report.JSON(os.Stdout, result)
	} else {
		report.Pretty(os.Stdout, result, *verbose)
	}

	if *exitCode && hasSerious(result.Findings, result.VulnDeps) {
		os.Exit(1)
	}
}

func hasSerious(findings []model.Finding, vulnDeps []model.VulnDep) bool {
	for _, f := range findings {
		if f.Confidence == model.Confirmed && (f.Severity == model.Critical || f.Severity == model.High) {
			return true
		}
	}
	for _, vd := range vulnDeps {
		if vd.Severity == model.Critical || vd.Severity == model.High {
			return true
		}
	}
	return false
}

func usage() {
	fmt.Fprintf(os.Stderr, `vibecheck %s - static security scanner for vibe-coded web apps

usage:
  vibecheck [path]              scan a directory (default: current dir)

flags:
  --json                 emit JSON for CI
  -v                     verbose: OWASP category + full explanation
  --min-severity S       only show findings >= S (critical/high/medium/low)
  --confirmed-only       show only confirmed findings, hide the review lane
  --frontend-only        scan frontend code only
  --backend-only         scan backend code only
  --no-sca               skip the dependency / supply-chain check
  --offline              never touch the network
  --timeout N            network timeout in seconds (default 25)
  --exit-code            exit non-zero on any confirmed critical/high (CI gate)
  --list                 print the rule catalogue
  --version              print version

vibecheck scans your OWN code. Findings are split into CONFIRMED (structural,
safe to act on) and REVIEW (heuristic, worth a look). Dependencies are checked
live against OSV.dev, so there's no local vulnerability database to update.
Docs: github.com/NotChaosuu/vibecheck
`, version)
}
