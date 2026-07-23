package sca

import (
	"testing"

	"github.com/NotChaosuu/vibecheck/internal/walk"
)

func mkf(name, content string) walk.File {
	return walk.File{Path: name, Name: name, Content: []byte(content)}
}

func find(deps []Dependency, eco, name string) (Dependency, bool) {
	for _, d := range deps {
		if d.Ecosystem == eco && d.Name == name {
			return d, true
		}
	}
	return Dependency{}, false
}

func TestParsePackageLockV3(t *testing.T) {
	lock := `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": { "name": "root", "version": "1.0.0" },
	    "node_modules/lodash": { "version": "4.17.15" },
	    "node_modules/@scope/pkg": { "version": "2.1.0" }
	  }
	}`
	deps := parsePackageLock(mkf("package-lock.json", lock))
	if d, ok := find(deps, "npm", "lodash"); !ok || d.Version != "4.17.15" {
		t.Errorf("lodash not parsed correctly: %+v", deps)
	}
	if _, ok := find(deps, "npm", "@scope/pkg"); !ok {
		t.Errorf("scoped package not parsed: %+v", deps)
	}
}

func TestParseGoMod(t *testing.T) {
	mod := `module example.com/app

go 1.22

require (
	github.com/gin-gonic/gin v1.9.0
	golang.org/x/net v0.17.0 // indirect
)

require github.com/stretchr/testify v1.8.4
`
	deps := parseGoMod(mkf("go.mod", mod))
	if _, ok := find(deps, "Go", "github.com/gin-gonic/gin"); !ok {
		t.Errorf("gin not parsed: %+v", deps)
	}
	if _, ok := find(deps, "Go", "github.com/stretchr/testify"); !ok {
		t.Errorf("single-line require not parsed: %+v", deps)
	}
	if _, ok := find(deps, "Go", "golang.org/x/net"); !ok {
		t.Errorf("indirect dep not parsed: %+v", deps)
	}
}

func TestParseRequirements(t *testing.T) {
	req := `# comment
Django==3.2.0
requests == 2.25.1
flask>=1.0        # unpinned, skip
-r other.txt
Jinja2==2.11.3 ; python_version < "3.8"
`
	deps := parseRequirements(mkf("requirements.txt", req))
	if _, ok := find(deps, "PyPI", "django"); !ok {
		t.Errorf("django not parsed: %+v", deps)
	}
	if _, ok := find(deps, "PyPI", "requests"); !ok {
		t.Errorf("requests (spaces) not parsed: %+v", deps)
	}
	if _, ok := find(deps, "PyPI", "jinja2"); !ok {
		t.Errorf("marker-suffixed pin not parsed: %+v", deps)
	}
	if _, ok := find(deps, "PyPI", "flask"); ok {
		t.Errorf("unpinned flask should be skipped: %+v", deps)
	}
}

func TestParsePoetryLock(t *testing.T) {
	lock := `[[package]]
name = "jinja2"
version = "2.4.1"
description = "templating"

[[package]]
name = "requests"
version = "2.25.1"
`
	deps := parsePoetryLock(mkf("poetry.lock", lock))
	if d, ok := find(deps, "PyPI", "jinja2"); !ok || d.Version != "2.4.1" {
		t.Errorf("jinja2 not parsed: %+v", deps)
	}
	if _, ok := find(deps, "PyPI", "requests"); !ok {
		t.Errorf("requests not parsed: %+v", deps)
	}
}

func TestParseYarnLock(t *testing.T) {
	lock := `# yarn lockfile v1
"lodash@^4.17.4", lodash@^4.17.15:
  version "4.17.15"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.15.tgz"

"@babel/core@^7.0.0":
  version "7.20.0"
`
	deps := parseYarnLock(mkf("yarn.lock", lock))
	if d, ok := find(deps, "npm", "lodash"); !ok || d.Version != "4.17.15" {
		t.Errorf("lodash not parsed from yarn.lock: %+v", deps)
	}
	if d, ok := find(deps, "npm", "@babel/core"); !ok || d.Version != "7.20.0" {
		t.Errorf("scoped yarn dep not parsed: %+v", deps)
	}
}

func TestLockfilePreferredOverManifest(t *testing.T) {
	files := []walk.File{
		mkf("package-lock.json", `{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.15"}}}`),
		mkf("requirements.txt", "django==3.2.0"),
		mkf("poetry.lock", "[[package]]\nname = \"django\"\nversion = \"4.0.0\"\n"),
	}
	deps := CollectDependencies(files)
	// poetry.lock present -> requirements.txt should be ignored for PyPI
	for _, d := range deps {
		if d.Ecosystem == "PyPI" && d.Version == "3.2.0" {
			t.Errorf("requirements.txt was used despite poetry.lock being present: %+v", deps)
		}
	}
	if _, ok := find(deps, "PyPI", "django"); !ok {
		t.Errorf("django (from poetry.lock) missing: %+v", deps)
	}
}
