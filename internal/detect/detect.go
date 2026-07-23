package detect

import (
	"path/filepath"
	"strings"

	"github.com/NotChaosuu/vibecheck/internal/walk"
)

type Stack struct {
	Languages  []string
	Frameworks []string
}

func Analyze(files []walk.File) Stack {
	langs := map[string]bool{}
	fw := map[string]bool{}

	for _, f := range files {
		switch f.Ext {
		case ".js", ".jsx", ".mjs", ".cjs":
			langs["JavaScript"] = true
		case ".ts", ".tsx":
			langs["TypeScript"] = true
		case ".py", ".pyw":
			langs["Python"] = true
		case ".go":
			langs["Go"] = true
		case ".vue":
			langs["JavaScript"] = true
			fw["Vue"] = true
		case ".svelte":
			langs["JavaScript"] = true
			fw["Svelte"] = true
		}

		lower := strings.ToLower(f.Name)
		switch {
		case lower == "next.config.js" || lower == "next.config.mjs" || lower == "next.config.ts":
			fw["Next.js"] = true
		case lower == "firestore.rules" || lower == "storage.rules" || lower == "database.rules.json":
			fw["Firebase"] = true
		case lower == "go.mod":
			langs["Go"] = true
		case lower == "requirements.txt" || lower == "pyproject.toml" || lower == "pipfile":
			langs["Python"] = true
		}

		sniffFrameworks(f, fw)
	}

	return Stack{Languages: keys(langs), Frameworks: keys(fw)}
}

func sniffFrameworks(f walk.File, fw map[string]bool) {
	body := string(f.Content)
	if f.Name == "package.json" {
		if strings.Contains(body, "\"next\"") {
			fw["Next.js"] = true
		}
		if strings.Contains(body, "\"react\"") {
			fw["React"] = true
		}
		if strings.Contains(body, "\"express\"") {
			fw["Express"] = true
		}
		if strings.Contains(body, "\"@supabase/supabase-js\"") {
			fw["Supabase"] = true
		}
		if strings.Contains(body, "\"firebase\"") {
			fw["Firebase"] = true
		}
		return
	}
	switch f.Ext {
	case ".py":
		if strings.Contains(body, "from fastapi") || strings.Contains(body, "import fastapi") {
			fw["FastAPI"] = true
		}
		if strings.Contains(body, "from flask") || strings.Contains(body, "import flask") {
			fw["Flask"] = true
		}
		if strings.Contains(body, "import django") || strings.Contains(body, "from django") {
			fw["Django"] = true
		}
	case ".ts", ".tsx", ".js", ".jsx":
		if strings.Contains(body, "from 'react'") || strings.Contains(body, "from \"react\"") {
			fw["React"] = true
		}
		if strings.Contains(body, "@supabase/supabase-js") {
			fw["Supabase"] = true
		}
		if strings.Contains(body, "require('express')") || strings.Contains(body, "from 'express'") {
			fw["Express"] = true
		}
	case ".sql":
		if strings.Contains(strings.ToLower(filepath.ToSlash(f.Path)), "supabase/") {
			fw["Supabase"] = true
		}
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}
