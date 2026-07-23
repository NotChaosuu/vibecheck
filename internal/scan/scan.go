package scan

import (
	"context"
	"time"

	"github.com/NotChaosuu/vibecheck/internal/analyze"
	"github.com/NotChaosuu/vibecheck/internal/detect"
	"github.com/NotChaosuu/vibecheck/internal/model"
	"github.com/NotChaosuu/vibecheck/internal/rules"
	"github.com/NotChaosuu/vibecheck/internal/sca"
	"github.com/NotChaosuu/vibecheck/internal/score"
	"github.com/NotChaosuu/vibecheck/internal/walk"
)

type Options struct {
	Target       string
	FrontendOnly bool
	BackendOnly  bool
	NoSCA        bool
	Offline      bool
	Timeout      time.Duration
	Status       func(string)
}

// Run wires the walker, detector, rules, analyzers, dependency check, and scorer
// into one Result. The SCA error is returned separately so a network hiccup
// degrades gracefully instead of sinking the code scan.
func Run(opts Options) (*model.Result, error) {
	status := opts.Status
	if status == nil {
		status = func(string) {}
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 25 * time.Second
	}

	files, err := walk.Collect(opts.Target, walk.DefaultOptions())
	if err != nil {
		return nil, err
	}
	files = filterScope(files, opts.FrontendOnly, opts.BackendOnly)

	stack := detect.Analyze(files)

	findings := rules.Run(files, rules.All())
	findings = append(findings, analyze.Project(files, opts.Target)...)

	var vulnDeps []model.VulnDep
	var scaErr error
	if !opts.NoSCA && !opts.Offline {
		status("checking dependencies against OSV.dev ...\n")
		ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout+5*time.Second)
		vulnDeps, _, scaErr = sca.Scan(ctx, files, opts.Timeout, false)
		cancel()
	}

	sc, grade, counts := score.Compute(findings, vulnDeps)

	return &model.Result{
		Target:       opts.Target,
		Languages:    stack.Languages,
		Frameworks:   stack.Frameworks,
		FilesScanned: len(files),
		Findings:     findings,
		VulnDeps:     vulnDeps,
		Grade:        grade,
		Score:        sc,
		Counts:       counts,
	}, scaErr
}

var frontendDrop = map[string]bool{".py": true, ".go": true}
var backendDrop = map[string]bool{".jsx": true, ".tsx": true, ".vue": true, ".svelte": true}

func filterScope(files []walk.File, frontendOnly, backendOnly bool) []walk.File {
	if !frontendOnly && !backendOnly {
		return files
	}
	var out []walk.File
	for _, f := range files {
		if frontendOnly && frontendDrop[f.Ext] {
			continue
		}
		if backendOnly && backendDrop[f.Ext] {
			continue
		}
		out = append(out, f)
	}
	return out
}
