package analyze

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/NotChaosuu/vibecheck/internal/model"
	"github.com/NotChaosuu/vibecheck/internal/walk"
)

// Project runs the detectors that need more than a single line of regex.
func Project(files []walk.File, root string) []model.Finding {
	var out []model.Finding
	for _, f := range files {
		out = append(out, corsWildcardCredentials(f)...)
		out = append(out, dangerouslySetInnerHTML(f)...)
		out = append(out, supabaseServiceRoleClient(f)...)
		out = append(out, missingRouteAuth(f)...)
	}
	out = append(out, supabaseMissingRLS(files)...)
	out = append(out, envNotGitignored(files, root)...)
	return out
}

func lineOf(content []byte, idx int) int {
	return 1 + strings.Count(string(content[:idx]), "\n")
}

func excerptAt(content []byte, idx int) string {
	start := idx
	for start > 0 && content[start-1] != '\n' {
		start--
	}
	end := idx
	for end < len(content) && content[end] != '\n' {
		end++
	}
	s := strings.TrimSpace(string(content[start:end]))
	if len(s) > 200 {
		return s[:197] + "..."
	}
	return s
}

var (
	corsWildcardOrigin = regexp.MustCompile(`(?i)(origin\s*:\s*['"]\*['"]|allow_origins\s*=\s*\[\s*['"]\*['"]\s*\]|origins\s*=\s*['"]\*['"]|Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*['"])`)
	corsCredentials    = regexp.MustCompile(`(?i)(credentials\s*:\s*true|allow_credentials\s*=\s*True|supports_credentials\s*=\s*True)`)
)

func corsWildcardCredentials(f walk.File) []model.Finding {
	switch f.Ext {
	case ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py":
	default:
		return nil
	}
	loc := corsWildcardOrigin.FindIndex(f.Content)
	if loc == nil || !corsCredentials.Match(f.Content) {
		return nil
	}
	return []model.Finding{{
		RuleID:     "cors-wildcard-credentials",
		Title:      "CORS allows any origin with credentials",
		Severity:   model.High,
		Confidence: model.Confirmed,
		OWASP:      "A05:2021 Security Misconfiguration",
		File:       f.Path,
		Line:       lineOf(f.Content, loc[0]),
		Excerpt:    excerptAt(f.Content, loc[0]),
		Detail:     "The CORS config pairs a wildcard origin with credentials, so any site can make authenticated cross-origin requests on behalf of a logged-in user.",
		Fix:        "Replace the wildcard with an explicit list of trusted origins.",
	}}
}

var dangerHTML = regexp.MustCompile(`(?s)dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*([^}]+)\}\}`)

func dangerouslySetInnerHTML(f walk.File) []model.Finding {
	switch f.Ext {
	case ".jsx", ".tsx", ".js", ".ts":
	default:
		return nil
	}
	var out []model.Finding
	for _, m := range dangerHTML.FindAllSubmatchIndex(f.Content, -1) {
		expr := strings.TrimSpace(string(f.Content[m[2]:m[3]]))
		if isConstantOrSanitized(expr) {
			continue
		}
		out = append(out, model.Finding{
			RuleID:     "react-dangerous-html",
			Title:      "dangerouslySetInnerHTML with an unsanitized value",
			Severity:   model.High,
			Confidence: model.Review,
			OWASP:      "A03:2021 Injection",
			File:       f.Path,
			Line:       lineOf(f.Content, m[0]),
			Excerpt:    excerptAt(f.Content, m[0]),
			Detail:     "A non-constant value is rendered as raw HTML. If any part is user-controlled this is stored/reflected XSS.",
			Fix:        "Wrap the value in DOMPurify.sanitize(...) before rendering.",
		})
	}
	return out
}

func isConstantOrSanitized(expr string) bool {
	if strings.Contains(expr, "DOMPurify") || strings.Contains(expr, "sanitize") || strings.Contains(expr, "xss(") {
		return true
	}
	if (strings.HasPrefix(expr, `"`) || strings.HasPrefix(expr, `'`)) && !strings.Contains(expr, "+") {
		return true
	}
	if strings.HasPrefix(expr, "`") && !strings.Contains(expr, "${") {
		return true
	}
	return false
}

var serviceRole = regexp.MustCompile(`(?i)(service_role|SUPABASE_SERVICE_ROLE_KEY)`)

func supabaseServiceRoleClient(f walk.File) []model.Finding {
	switch f.Ext {
	case ".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte":
	default:
		return nil
	}
	if !strings.Contains(string(f.Content), "createClient") {
		return nil
	}
	loc := serviceRole.FindIndex(f.Content)
	if loc == nil {
		return nil
	}
	return []model.Finding{{
		RuleID:     "supabase-service-role-client",
		Title:      "Supabase service_role key used in client code",
		Severity:   model.Critical,
		Confidence: model.Review,
		OWASP:      "A01:2021 Broken Access Control",
		File:       f.Path,
		Line:       lineOf(f.Content, loc[0]),
		Excerpt:    excerptAt(f.Content, loc[0]),
		Detail:     "The service_role key bypasses Row Level Security entirely. In client-reachable code it hands every row to anyone who opens the app.",
		Fix:        "Use the anon key on the client. Keep service_role on the server only.",
	}}
}

// Plain Postgres / Prisma / Drizzle apps do authz in code, not with RLS, so the
// RLS rules only run when the project actually uses Supabase.
func isSupabaseProject(files []walk.File) bool {
	for _, f := range files {
		if strings.Contains(strings.ToLower(f.Path), "supabase") {
			return true
		}
		body := string(f.Content)
		if strings.Contains(body, "@supabase/supabase-js") ||
			strings.Contains(body, "supabase.co") ||
			(strings.Contains(body, "createClient") && strings.Contains(body, "supabase")) {
			return true
		}
	}
	return false
}

var (
	createTable = regexp.MustCompile(`(?i)create\s+table\s+(?:if\s+not\s+exists\s+)?("?[\w.]+"?)`)
	enableRLS   = regexp.MustCompile(`(?i)alter\s+table\s+("?[\w.]+"?)\s+enable\s+row\s+level\s+security`)
	disableRLS  = regexp.MustCompile(`(?i)alter\s+table\s+("?[\w.]+"?)\s+disable\s+row\s+level\s+security`)
)

func normTable(s string) string {
	s = strings.Trim(strings.ToLower(s), `"`)
	if i := strings.LastIndex(s, "."); i >= 0 {
		s = s[i+1:]
	}
	return s
}

func supabaseMissingRLS(files []walk.File) []model.Finding {
	if !isSupabaseProject(files) {
		return nil
	}
	type loc struct {
		file string
		line int
		raw  string
	}
	created := map[string]loc{}
	enabled := map[string]bool{}
	var out []model.Finding

	sawSQL := false
	for _, f := range files {
		if f.Ext != ".sql" {
			continue
		}
		sawSQL = true
		for _, m := range createTable.FindAllSubmatchIndex(f.Content, -1) {
			name := normTable(string(f.Content[m[2]:m[3]]))
			if _, ok := created[name]; !ok {
				created[name] = loc{f.Path, lineOf(f.Content, m[0]), excerptAt(f.Content, m[0])}
			}
		}
		for _, m := range enableRLS.FindAllSubmatch(f.Content, -1) {
			enabled[normTable(string(m[1]))] = true
		}
		for _, m := range disableRLS.FindAllSubmatchIndex(f.Content, -1) {
			out = append(out, model.Finding{
				RuleID:     "supabase-rls-disabled",
				Title:      "Row Level Security explicitly disabled",
				Severity:   model.Critical,
				Confidence: model.Confirmed,
				OWASP:      "A01:2021 Broken Access Control",
				File:       f.Path,
				Line:       lineOf(f.Content, m[0]),
				Excerpt:    excerptAt(f.Content, m[0]),
				Detail:     "A migration turns RLS off on a table. Every row becomes readable/writable through the public anon key.",
				Fix:        "Re-enable RLS and add per-user policies.",
			})
		}
	}
	if !sawSQL {
		return out
	}

	for name, l := range created {
		if enabled[name] {
			continue
		}
		out = append(out, model.Finding{
			RuleID:     "supabase-missing-rls",
			Title:      "Table created without Row Level Security",
			Severity:   model.High,
			Confidence: model.Review,
			OWASP:      "A01:2021 Broken Access Control",
			File:       l.file,
			Line:       l.line,
			Excerpt:    l.raw,
			Detail:     "This table has no matching `enable row level security`. Tables created via SQL default to RLS off, so it may be world-readable through the anon key. This is the CVE-2025-48757 class that leaked 170+ apps. Verify with: select tablename, rowsecurity from pg_tables where schemaname='public'.",
			Fix:        "alter table " + name + " enable row level security; then add per-user policies.",
		})
	}
	return out
}

var (
	apiRoutePath = regexp.MustCompile(`(?i)(^|/)(pages/api/|app/.*/route\.(ts|js|tsx|jsx)$|api/)`)
	dbCall       = regexp.MustCompile(`(?i)(prisma\.|db\.|\.findMany\(|\.findUnique\(|\.create\(|\.update\(|\.delete\(|supabase\.from\(|sequelize\.|knex\(|mongoose\.|collection\()`)
	authToken    = regexp.MustCompile(`(?i)(getServerSession|getToken|requireAuth|verifyToken|verifyJwt|currentUser|clerk|withAuth|req\.user|session\?|await auth\(|isAuthenticated|Depends\(|@login_required|@requires_auth)`)
	adminPath    = regexp.MustCompile(`(?i)(admin|delete|internal|/user)`)
)

func missingRouteAuth(f walk.File) []model.Finding {
	switch f.Ext {
	case ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs":
	default:
		return nil
	}
	if !apiRoutePath.MatchString(f.Path) {
		return nil
	}
	loc := dbCall.FindIndex(f.Content)
	if loc == nil || authToken.Match(f.Content) {
		return nil
	}
	sev := model.Medium
	if adminPath.MatchString(f.Path) {
		sev = model.High
	}
	return []model.Finding{{
		RuleID:     "missing-route-auth",
		Title:      "API route touches data with no auth check",
		Severity:   sev,
		Confidence: model.Review,
		OWASP:      "A01:2021 Broken Access Control",
		File:       f.Path,
		Line:       lineOf(f.Content, loc[0]),
		Excerpt:    excerptAt(f.Content, loc[0]),
		Detail:     "This route runs a database operation but contains none of the usual auth guards. If the endpoint isn't meant to be public, anyone can call it.",
		Fix:        "Add an auth check at the top of the handler and return 401 when it fails.",
	}}
}

func envNotGitignored(files []walk.File, root string) []model.Finding {
	var envFiles []walk.File
	for _, f := range files {
		if f.Name == ".env" || f.Name == ".env.local" || f.Name == ".env.production" || f.Name == ".env.development" {
			envFiles = append(envFiles, f)
		}
	}
	if len(envFiles) == 0 {
		return nil
	}
	ignored := gitignorePatterns(root)
	var out []model.Finding
	for _, f := range envFiles {
		if ignored[f.Name] || ignored[".env"] || ignored[".env*"] || ignored["*.env"] {
			continue
		}
		out = append(out, model.Finding{
			RuleID:     "env-not-gitignored",
			Title:      "Environment file not covered by .gitignore",
			Severity:   model.High,
			Confidence: model.Review,
			OWASP:      "A05:2021 Security Misconfiguration",
			File:       f.Path,
			Line:       1,
			Detail:     f.Name + " holds secrets and isn't matched by .gitignore, so it can be committed and pushed.",
			Fix:        "Add " + f.Name + " (or .env*) to .gitignore and make sure it isn't already tracked.",
		})
	}
	return out
}

func gitignorePatterns(root string) map[string]bool {
	out := map[string]bool{}
	data, err := os.ReadFile(filepath.Join(root, ".gitignore"))
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out[strings.TrimPrefix(line, "/")] = true
	}
	return out
}
