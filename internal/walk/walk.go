package walk

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

var skipDirs = map[string]bool{
	"node_modules": true,
	".git":         true,
	".svn":         true,
	".hg":          true,
	"vendor":       true,
	"dist":         true,
	"build":        true,
	"out":          true,
	".next":        true,
	".nuxt":        true,
	".svelte-kit":  true,
	"coverage":     true,
	"__pycache__":  true,
	".venv":        true,
	"venv":         true,
	"env":          true,
	".idea":        true,
	".vscode":      true,
	".cache":       true,
	"target":       true,
	"bin":          true,
	"obj":          true,
}

var scanExt = map[string]bool{
	".js": true, ".jsx": true, ".ts": true, ".tsx": true, ".mjs": true, ".cjs": true,
	".py": true, ".pyw": true,
	".go":    true,
	".rules": true,
	".sql":   true,
	".json":  true, ".env": true,
	".yaml": true, ".yml": true,
	".vue": true, ".svelte": true,
}

// alwaysScanNames covers env files, cloud rules, and dependency manifests that
// have no scannable extension of their own.
var alwaysScanNames = map[string]bool{
	".env": true, ".env.local": true, ".env.production": true, ".env.development": true,
	"firestore.rules": true, "storage.rules": true, "database.rules.json": true,
	"next.config.js": true, "next.config.mjs": true, "next.config.ts": true,
	"package.json": true, "package-lock.json": true, "yarn.lock": true,
	"requirements.txt": true, "poetry.lock": true, "pipfile.lock": true, "pipfile": true,
	"go.mod": true, "go.sum": true,
}

type File struct {
	Path    string
	AbsPath string
	Ext     string
	Name    string
	Content []byte
}

type Options struct {
	MaxFileBytes int64
}

func DefaultOptions() Options {
	return Options{MaxFileBytes: 2 * 1024 * 1024}
}

func Collect(root string, opts Options) ([]File, error) {
	if opts.MaxFileBytes <= 0 {
		opts.MaxFileBytes = 2 * 1024 * 1024
	}
	var files []File

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		name := d.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if !scanExt[ext] && !alwaysScanNames[name] {
			return nil
		}

		info, err := d.Info()
		if err != nil || info.Size() > opts.MaxFileBytes {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil || looksBinary(content) {
			return nil
		}

		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			rel = path
		}
		files = append(files, File{
			Path:    filepath.ToSlash(rel),
			AbsPath: path,
			Ext:     ext,
			Name:    name,
			Content: content,
		})
		return nil
	})
	return files, err
}

func looksBinary(b []byte) bool {
	n := len(b)
	if n > 512 {
		n = 512
	}
	for i := 0; i < n; i++ {
		if b[i] == 0 {
			return true
		}
	}
	return false
}
