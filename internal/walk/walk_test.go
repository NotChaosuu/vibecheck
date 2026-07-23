package walk

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCollectsManifestsAndSkipsNoise(t *testing.T) {
	dir := t.TempDir()
	writeFile := func(rel, content string) {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// manifests with no scannable extension must still be collected
	writeFile("requirements.txt", "django==3.2.0")
	writeFile("go.mod", "module x\n")
	writeFile("yarn.lock", "# yarn\n")
	writeFile("package-lock.json", "{}")
	writeFile("app.py", "print('hi')")
	// noise that must be skipped
	writeFile("node_modules/lodash/index.js", "module.exports = {}")
	writeFile(".git/config", "[core]")
	writeFile("dist/bundle.js", "console.log(1)")

	files, err := Collect(dir, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range files {
		got[f.Path] = true
	}

	for _, want := range []string{"requirements.txt", "go.mod", "yarn.lock", "package-lock.json", "app.py"} {
		if !got[want] {
			t.Errorf("expected %q to be collected", want)
		}
	}
	for _, skip := range []string{"node_modules/lodash/index.js", ".git/config", "dist/bundle.js"} {
		if got[skip] {
			t.Errorf("expected %q to be skipped", skip)
		}
	}
}
