package rules

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/NotChaosuu/vibecheck/internal/model"
	"github.com/NotChaosuu/vibecheck/internal/walk"
)

var testDirs = []string{
	"/test/", "/tests/", "/__tests__/", "/spec/", "/specs/", "/e2e/",
	"/benchmark/", "/benchmarks/", "/fixtures/", "/fixture/", "/mocks/",
	"/__mocks__/", "/examples/", "/example/", "/testdata/",
}

var testNameMarkers = []string{".test.", ".spec.", "_test.", "-test.", ".stories."}

func isTestPath(p string) bool {
	lp := "/" + strings.ToLower(filepath.ToSlash(p)) + "/"
	for _, d := range testDirs {
		if strings.Contains(lp, d) {
			return true
		}
	}
	base := strings.ToLower(filepath.Base(p))
	for _, m := range testNameMarkers {
		if strings.Contains(base, m) {
			return true
		}
	}
	return false
}

type Rule struct {
	ID         string
	Title      string
	Severity   model.Severity
	Confidence model.Confidence
	OWASP      string
	Detail     string
	Fix        string

	Pattern   *regexp.Regexp
	Allow     []*regexp.Regexp
	Multiline bool

	Exts        []string
	Names       []string
	PathHint    *regexp.Regexp
	SkipInTests bool

	Custom func(f walk.File) []model.Finding
}

func (r Rule) applies(f walk.File) bool {
	if r.PathHint != nil && !r.PathHint.MatchString(f.Path) {
		return false
	}
	if len(r.Exts) == 0 && len(r.Names) == 0 {
		return true
	}
	for _, e := range r.Exts {
		if f.Ext == e {
			return true
		}
	}
	for _, n := range r.Names {
		if strings.EqualFold(f.Name, n) {
			return true
		}
	}
	return false
}

func (r Rule) suppressed(hit string) bool {
	for _, a := range r.Allow {
		if a.MatchString(hit) {
			return true
		}
	}
	return false
}

func Run(files []walk.File, catalogue []Rule) []model.Finding {
	var out []model.Finding
	for _, f := range files {
		for _, r := range catalogue {
			if !r.applies(f) {
				continue
			}
			if r.Custom != nil {
				out = append(out, r.Custom(f)...)
				continue
			}
			out = append(out, r.scan(f)...)
		}
	}
	return out
}

func (r Rule) scan(f walk.File) []model.Finding {
	if r.Pattern == nil {
		return nil
	}
	if r.SkipInTests && isTestPath(f.Path) {
		return nil
	}
	var out []model.Finding
	content := f.Content

	if r.Multiline {
		for _, loc := range r.Pattern.FindAllIndex(content, -1) {
			hit := string(content[loc[0]:loc[1]])
			if r.suppressed(hit) {
				continue
			}
			line := 1 + strings.Count(string(content[:loc[0]]), "\n")
			out = append(out, r.finding(f, line, firstLine(hit)))
		}
		return out
	}

	lineNo := 0
	for _, raw := range strings.Split(string(content), "\n") {
		lineNo++
		line := strings.TrimRight(raw, "\r")
		if !r.Pattern.MatchString(line) || r.suppressed(line) {
			continue
		}
		out = append(out, r.finding(f, lineNo, line))
	}
	return out
}

func (r Rule) finding(f walk.File, line int, excerpt string) model.Finding {
	return model.Finding{
		RuleID:     r.ID,
		Title:      r.Title,
		Severity:   r.Severity,
		Confidence: r.Confidence,
		OWASP:      r.OWASP,
		File:       f.Path,
		Line:       line,
		Excerpt:    trimExcerpt(excerpt),
		Detail:     r.Detail,
		Fix:        r.Fix,
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func trimExcerpt(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		return s[:197] + "..."
	}
	return s
}

func mustRE(p string) *regexp.Regexp { return regexp.MustCompile(p) }

func reList(pats ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(pats))
	for _, p := range pats {
		out = append(out, regexp.MustCompile(p))
	}
	return out
}
