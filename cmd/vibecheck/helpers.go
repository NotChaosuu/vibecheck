package main

import (
	"fmt"
	"os"

	"github.com/NotChaosuu/vibecheck/internal/model"
	"github.com/NotChaosuu/vibecheck/internal/rules"
)

// specialRuleCount is the detector count from the analyze package (not in rules.All()).
const specialRuleCount = 7

func sevCutoff(minSev string) (int, bool) {
	r, ok := model.SeverityRank[model.Severity(minSev)]
	return r, ok
}

func filterFindings(findings []model.Finding, minSev string, confirmedOnly bool) []model.Finding {
	cutoff, hasCutoff := sevCutoff(minSev)
	var out []model.Finding
	for _, f := range findings {
		if confirmedOnly && f.Confidence != model.Confirmed {
			continue
		}
		if hasCutoff && model.SeverityRank[f.Severity] > cutoff {
			continue
		}
		out = append(out, f)
	}
	return out
}

func filterVulnDeps(vds []model.VulnDep, minSev string) []model.VulnDep {
	cutoff, hasCutoff := sevCutoff(minSev)
	if !hasCutoff {
		return vds
	}
	var out []model.VulnDep
	for _, vd := range vds {
		if model.SeverityRank[vd.Severity] <= cutoff {
			out = append(out, vd)
		}
	}
	return out
}

func listRules() {
	fmt.Printf("vibecheck rule catalogue (%d rules)\n\n", rules.Count()+specialRuleCount)
	for _, r := range rules.All() {
		fmt.Fprintf(os.Stdout, "  %-32s %-8s %-9s %s\n", r.ID, r.Severity, r.Confidence, r.Title)
	}
	specials := []struct{ id, sev, conf, title string }{
		{"cors-wildcard-credentials", "high", "confirmed", "CORS allows any origin with credentials"},
		{"react-dangerous-html", "high", "review", "dangerouslySetInnerHTML with an unsanitized value"},
		{"supabase-service-role-client", "critical", "review", "Supabase service_role key used in client code"},
		{"supabase-missing-rls", "high", "review", "Table created without Row Level Security"},
		{"supabase-rls-disabled", "critical", "confirmed", "Row Level Security explicitly disabled"},
		{"missing-route-auth", "medium", "review", "API route touches data with no auth check"},
		{"env-not-gitignored", "high", "review", "Environment file not covered by .gitignore"},
	}
	for _, r := range specials {
		fmt.Fprintf(os.Stdout, "  %-32s %-8s %-9s %s\n", r.id, r.sev, r.conf, r.title)
	}
}
