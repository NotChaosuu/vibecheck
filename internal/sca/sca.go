package sca

import (
	"context"
	"strings"
	"time"

	"github.com/NotChaosuu/vibecheck/internal/model"
	"github.com/NotChaosuu/vibecheck/internal/walk"
)

type Dependency = model.Dependency

// Scan resolves dependencies and checks them against OSV.dev. A network error
// returns the parsed count with no vuln findings rather than failing the scan.
func Scan(ctx context.Context, files []walk.File, timeout time.Duration, offline bool) ([]model.VulnDep, int, error) {
	deps := CollectDependencies(files)
	if offline || len(deps) == 0 {
		return nil, len(deps), nil
	}

	client := NewClient(timeout)
	idsPerDep, err := client.queryBatch(ctx, deps)
	if err != nil {
		return nil, len(deps), err
	}

	var out []model.VulnDep
	for i, ids := range idsPerDep {
		if len(ids) == 0 {
			continue
		}
		dep := deps[i]
		vd := model.VulnDep{Dependency: dep, Severity: model.Info}
		for _, id := range ids {
			rec, gerr := client.getVuln(ctx, id)
			if gerr != nil {
				continue
			}
			sev := severityFromRecord(rec)
			vd.Vulns = append(vd.Vulns, model.DepVuln{
				ID:       rec.ID,
				Aliases:  rec.Aliases,
				Summary:  firstNonEmpty(rec.Summary, rec.Details),
				Severity: sev,
				Fixed:    rec.fixedVersion(dep.Name),
				URL:      rec.primaryURL(),
			})
			vd.Severity = model.WorstSeverity(vd.Severity, sev)
		}
		if len(vd.Vulns) > 0 {
			out = append(out, vd)
		}
	}
	return out, len(deps), nil
}

func severityFromRecord(r *osvRecord) model.Severity {
	switch strings.ToUpper(r.DatabaseSpecific.Severity) {
	case "CRITICAL":
		return model.Critical
	case "HIGH":
		return model.High
	case "MODERATE", "MEDIUM":
		return model.Medium
	case "LOW":
		return model.Low
	}
	return model.Medium
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return strings.TrimSpace(b)
}
