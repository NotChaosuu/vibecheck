package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/NotChaosuu/vibecheck/internal/model"
)

var (
	useColor = detectColor()
	bold     = c("\x1b[1m")
	dim      = c("\x1b[2m")
	reset    = c("\x1b[0m")
	green    = c("\x1b[92m")
	yellow   = c("\x1b[93m")
	red      = c("\x1b[91m")
	cyan     = c("\x1b[96m")
	magenta  = c("\x1b[95m")
)

func detectColor() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func c(code string) string {
	if !useColor {
		return ""
	}
	return code
}

func sevColor(s model.Severity) string {
	switch s {
	case model.Critical, model.High:
		return red
	case model.Medium:
		return yellow
	case model.Low:
		return cyan
	default:
		return dim
	}
}

func gradeColor(g string) string {
	switch g {
	case "A", "B":
		return green
	case "C":
		return yellow
	default:
		return red
	}
}

func Sort(r *model.Result) {
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.Confidence != b.Confidence {
			return a.Confidence == model.Confirmed
		}
		if a.Severity != b.Severity {
			return model.SeverityRank[a.Severity] < model.SeverityRank[b.Severity]
		}
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	sort.SliceStable(r.VulnDeps, func(i, j int) bool {
		return model.SeverityRank[r.VulnDeps[i].Severity] < model.SeverityRank[r.VulnDeps[j].Severity]
	})
}

func Pretty(w io.Writer, r *model.Result, verbose bool) {
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %svibecheck%s  %s%s%s\n", bold, reset, dim, r.Target, reset)
	fmt.Fprintln(w)

	gc := gradeColor(r.Grade)
	fmt.Fprintf(w, "  Security grade:  %s%s%s  %s(%d/100)%s\n", gc+bold, r.Grade, reset, dim, r.Score, reset)
	fmt.Fprintf(w, "  Findings:        %s\n", countLine(r.Counts))
	if len(r.Languages) > 0 {
		fmt.Fprintf(w, "  Languages:       %s\n", join(r.Languages))
	}
	if len(r.Frameworks) > 0 {
		fmt.Fprintf(w, "  Frameworks:      %s\n", join(r.Frameworks))
	}
	fmt.Fprintf(w, "  Files scanned:   %d\n", r.FilesScanned)

	confirmed := filterConfidence(r.Findings, model.Confirmed)
	review := filterConfidence(r.Findings, model.Review)

	if len(confirmed) > 0 {
		fmt.Fprintf(w, "\n  %s%sCONFIRMED (%d)%s  %sstructural, safe to act on%s\n", red, bold, len(confirmed), reset, dim, reset)
		printFindings(w, confirmed, verbose)
	}
	if len(review) > 0 {
		fmt.Fprintf(w, "\n  %s%sREVIEW (%d)%s  %sheuristic, worth a look%s\n", yellow, bold, len(review), reset, dim, reset)
		printFindings(w, review, verbose)
	}
	if len(r.VulnDeps) > 0 {
		fmt.Fprintf(w, "\n  %s%sVULNERABLE DEPENDENCIES (%d)%s  %svia OSV.dev%s\n", magenta, bold, len(r.VulnDeps), reset, dim, reset)
		printVulnDeps(w, r.VulnDeps, verbose)
	}

	if len(confirmed) == 0 && len(review) == 0 && len(r.VulnDeps) == 0 {
		fmt.Fprintf(w, "\n  %sNo issues found.%s\n", green, reset)
	}
	fmt.Fprintln(w)
}

func printFindings(w io.Writer, fs []model.Finding, verbose bool) {
	for _, f := range fs {
		sc := sevColor(f.Severity)
		fmt.Fprintf(w, "    %s%-8s%s %s\n", sc+bold, up(f.Severity), reset, f.Title)
		fmt.Fprintf(w, "      %s%s:%d%s  %s[%s]%s\n", cyan, f.File, f.Line, reset, dim, f.RuleID, reset)
		if f.Excerpt != "" {
			fmt.Fprintf(w, "      %s%s%s\n", dim, f.Excerpt, reset)
		}
		if verbose {
			if f.OWASP != "" {
				fmt.Fprintf(w, "      %sowasp:%s %s\n", dim, reset, f.OWASP)
			}
			fmt.Fprintf(w, "      %swhy:%s   %s\n", dim, reset, f.Detail)
		}
		fmt.Fprintf(w, "      %sfix:%s   %s\n", dim, reset, f.Fix)
		fmt.Fprintln(w)
	}
}

func printVulnDeps(w io.Writer, vds []model.VulnDep, verbose bool) {
	for _, vd := range vds {
		sc := sevColor(vd.Severity)
		d := vd.Dependency
		fmt.Fprintf(w, "    %s%-8s%s %s@%s %s(%s)%s\n", sc+bold, up(vd.Severity), reset, d.Name, d.Version, dim, d.Ecosystem, reset)
		for _, v := range vd.Vulns {
			fixed := ""
			if v.Fixed != "" {
				fixed = fmt.Sprintf(" %sfixed in %s%s", dim, v.Fixed, reset)
			}
			fmt.Fprintf(w, "      %s%s%s %s%s\n", cyan, v.ID, reset, trunc(v.Summary, 80), fixed)
			if verbose && v.URL != "" {
				fmt.Fprintf(w, "        %s%s%s\n", dim, v.URL, reset)
			}
		}
		fmt.Fprintln(w)
	}
}

func JSON(w io.Writer, r *model.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func countLine(cnt model.CountsBySev) string {
	parts := []struct {
		n     int
		label string
		col   string
	}{
		{cnt.Critical, "critical", red},
		{cnt.High, "high", red},
		{cnt.Medium, "medium", yellow},
		{cnt.Low, "low", cyan},
	}
	out := ""
	for _, p := range parts {
		if p.n == 0 {
			continue
		}
		if out != "" {
			out += "  "
		}
		out += fmt.Sprintf("%s%d %s%s", p.col, p.n, p.label, reset)
	}
	if out == "" {
		return green + "none" + reset
	}
	return out
}

func filterConfidence(fs []model.Finding, conf model.Confidence) []model.Finding {
	var out []model.Finding
	for _, f := range fs {
		if f.Confidence == conf {
			out = append(out, f)
		}
	}
	return out
}

func up(s model.Severity) string {
	switch s {
	case model.Critical:
		return "CRIT"
	case model.High:
		return "HIGH"
	case model.Medium:
		return "MED"
	case model.Low:
		return "LOW"
	default:
		return "INFO"
	}
}

func join(items []string) string {
	out := ""
	for i, s := range items {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
