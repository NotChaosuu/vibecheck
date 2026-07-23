package sca

import (
	"context"
	"testing"
	"time"

	"github.com/NotChaosuu/vibecheck/internal/model"
	"github.com/NotChaosuu/vibecheck/internal/walk"
)

// TestOSVLive hits the real OSV.dev API with a package version that has a
// long-standing known advisory. It's skipped automatically when the network
// is unavailable so it never breaks an offline build.
func TestOSVLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live OSV query in -short mode")
	}

	// jinja2 2.4.1 (PyPI) and lodash 4.17.15 (npm) both carry known advisories.
	files := []walk.File{
		mkf("requirements.txt", "jinja2==2.4.1\n"),
		mkf("package-lock.json", `{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.15"}}}`),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	vulnDeps, depCount, err := Scan(ctx, files, 15*time.Second, false)
	if err != nil {
		t.Skipf("OSV query failed (offline?): %v", err)
	}
	if depCount != 2 {
		t.Fatalf("expected 2 dependencies parsed, got %d", depCount)
	}
	if len(vulnDeps) == 0 {
		t.Fatal("expected OSV to report advisories for jinja2 2.4.1 / lodash 4.17.15, got none")
	}

	// Each reported dep should carry at least one advisory with an ID.
	for _, vd := range vulnDeps {
		if len(vd.Vulns) == 0 {
			t.Errorf("%s@%s reported with no advisories", vd.Dependency.Name, vd.Dependency.Version)
		}
		for _, v := range vd.Vulns {
			if v.ID == "" {
				t.Errorf("advisory with empty ID on %s", vd.Dependency.Name)
			}
		}
		if vd.Severity == model.Info {
			t.Errorf("%s reported at info severity; expected a real severity", vd.Dependency.Name)
		}
	}
	t.Logf("OSV live: %d vulnerable deps found", len(vulnDeps))
}
