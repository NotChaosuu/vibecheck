package sca

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/NotChaosuu/vibecheck/internal/model"
	"github.com/NotChaosuu/vibecheck/internal/walk"
)

// CollectDependencies resolves (ecosystem, name, version) tuples from the
// manifests and lockfiles in the tree. Lockfiles win over manifests since they
// carry exact resolved versions.
func CollectDependencies(files []walk.File) []model.Dependency {
	var deps []model.Dependency
	haveLock := map[string]bool{}

	for _, f := range files {
		switch strings.ToLower(f.Name) {
		case "package-lock.json":
			deps = append(deps, parsePackageLock(f)...)
			haveLock["npm"] = true
		case "poetry.lock":
			deps = append(deps, parsePoetryLock(f)...)
			haveLock["PyPI"] = true
		case "pipfile.lock":
			deps = append(deps, parsePipfileLock(f)...)
			haveLock["PyPI"] = true
		case "yarn.lock":
			deps = append(deps, parseYarnLock(f)...)
			haveLock["npm"] = true
		case "go.mod":
			deps = append(deps, parseGoMod(f)...)
			haveLock["Go"] = true
		}
	}
	for _, f := range files {
		if strings.ToLower(f.Name) == "requirements.txt" && !haveLock["PyPI"] {
			deps = append(deps, parseRequirements(f)...)
		}
	}
	return dedupe(deps)
}

func dedupe(in []model.Dependency) []model.Dependency {
	seen := map[string]bool{}
	var out []model.Dependency
	for _, d := range in {
		if d.Name == "" || d.Version == "" {
			continue
		}
		k := d.Ecosystem + "|" + d.Name + "|" + d.Version
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, d)
	}
	return out
}

func parsePackageLock(f walk.File) []model.Dependency {
	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(f.Content, &lock); err != nil {
		return nil
	}
	var out []model.Dependency
	if len(lock.Packages) > 0 {
		for path, p := range lock.Packages {
			if path == "" || p.Version == "" {
				continue
			}
			name := path
			if i := strings.LastIndex(path, "node_modules/"); i >= 0 {
				name = path[i+len("node_modules/"):]
			}
			out = append(out, model.Dependency{Ecosystem: "npm", Name: name, Version: p.Version, Manifest: f.Path})
		}
		return out
	}
	for name, p := range lock.Dependencies {
		out = append(out, model.Dependency{Ecosystem: "npm", Name: name, Version: p.Version, Manifest: f.Path})
	}
	return out
}

var yarnVersion = regexp.MustCompile(`^\s+version:?\s+"?([^"\s]+)"?`)

func parseYarnLock(f walk.File) []model.Dependency {
	var out []model.Dependency
	var header string
	for _, raw := range strings.Split(string(f.Content), "\n") {
		line := strings.TrimRight(raw, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(strings.TrimSpace(line), ":") {
			header = line
			continue
		}
		if m := yarnVersion.FindStringSubmatch(line); m != nil && header != "" {
			if name := yarnName(header); name != "" {
				out = append(out, model.Dependency{Ecosystem: "npm", Name: name, Version: m[1], Manifest: f.Path})
			}
			header = ""
		}
	}
	return out
}

func yarnName(header string) string {
	header = strings.TrimSuffix(strings.TrimSpace(header), ":")
	first := strings.SplitN(header, ",", 2)[0]
	first = strings.Trim(strings.TrimSpace(first), `"`)
	if strings.HasPrefix(first, "@") {
		if i := strings.Index(first[1:], "@"); i >= 0 {
			return first[:i+1]
		}
		return first
	}
	if i := strings.Index(first, "@"); i >= 0 {
		return first[:i]
	}
	return first
}

var goRequireLine = regexp.MustCompile(`^\s*([^\s]+)\s+(v[^\s/]+)`)

func parseGoMod(f walk.File) []model.Dependency {
	var out []model.Dependency
	inBlock := false
	for _, raw := range strings.Split(string(f.Content), "\n") {
		trimmed := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		switch {
		case strings.HasPrefix(trimmed, "require ("):
			inBlock = true
		case inBlock && trimmed == ")":
			inBlock = false
		case strings.HasPrefix(trimmed, "require "):
			if m := goRequireLine.FindStringSubmatch(strings.TrimPrefix(trimmed, "require ")); m != nil {
				out = append(out, model.Dependency{Ecosystem: "Go", Name: m[1], Version: strings.TrimSuffix(m[2], "+incompatible"), Manifest: f.Path})
			}
		case inBlock:
			if m := goRequireLine.FindStringSubmatch(trimmed); m != nil {
				out = append(out, model.Dependency{Ecosystem: "Go", Name: m[1], Version: strings.TrimSuffix(m[2], "+incompatible"), Manifest: f.Path})
			}
		}
	}
	return out
}

var reqPin = regexp.MustCompile(`^([A-Za-z0-9._\-]+)\s*==\s*([A-Za-z0-9._\-]+)`)

func parseRequirements(f walk.File) []model.Dependency {
	var out []model.Dependency
	for _, raw := range strings.Split(string(f.Content), "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if i := strings.IndexAny(line, ";#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if m := reqPin.FindStringSubmatch(line); m != nil {
			out = append(out, model.Dependency{Ecosystem: "PyPI", Name: normalizePyPI(m[1]), Version: m[2], Manifest: f.Path})
		}
	}
	return out
}

func parsePoetryLock(f walk.File) []model.Dependency {
	var out []model.Dependency
	var name, version string
	flush := func() {
		if name != "" && version != "" {
			out = append(out, model.Dependency{Ecosystem: "PyPI", Name: normalizePyPI(name), Version: version, Manifest: f.Path})
		}
		name, version = "", ""
	}
	for _, raw := range strings.Split(string(f.Content), "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "[[package]]" {
			flush()
			continue
		}
		if v, ok := tomlString(line, "name"); ok {
			name = v
		}
		if v, ok := tomlString(line, "version"); ok {
			version = v
		}
	}
	flush()
	return out
}

func tomlString(line, key string) (string, bool) {
	prefix := key + " = "
	if !strings.HasPrefix(line, prefix) {
		return "", false
	}
	return strings.Trim(strings.TrimPrefix(line, prefix), `"`), true
}

func parsePipfileLock(f walk.File) []model.Dependency {
	var lock struct {
		Default map[string]struct {
			Version string `json:"version"`
		} `json:"default"`
		Develop map[string]struct {
			Version string `json:"version"`
		} `json:"develop"`
	}
	if err := json.Unmarshal(f.Content, &lock); err != nil {
		return nil
	}
	var out []model.Dependency
	add := func(m map[string]struct {
		Version string `json:"version"`
	}) {
		for name, p := range m {
			out = append(out, model.Dependency{Ecosystem: "PyPI", Name: normalizePyPI(name), Version: strings.TrimPrefix(p.Version, "=="), Manifest: f.Path})
		}
	}
	add(lock.Default)
	add(lock.Develop)
	return out
}

func normalizePyPI(name string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(name), "_", "-"))
}
