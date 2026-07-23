package analyze

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/NotChaosuu/vibecheck/internal/walk"
)

func mk(path, ext, content string) walk.File {
	return walk.File{Path: path, Name: filepath.Base(path), Ext: ext, Content: []byte(content)}
}

func hasRule(ruleID string, files []walk.File, root string) bool {
	for _, f := range Project(files, root) {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

func TestCORSWildcardCredentials(t *testing.T) {
	vuln := mk("server.js", ".js", `app.use(cors({ origin: '*', credentials: true }))`)
	safe := mk("server.js", ".js", `app.use(cors({ origin: ['https://app.example.com'], credentials: true }))`)
	// credentials-less wildcard is not the critical combo
	wildOnly := mk("server.js", ".js", `app.use(cors({ origin: '*' }))`)

	if !hasRule("cors-wildcard-credentials", []walk.File{vuln}, ".") {
		t.Error("recall miss: CORS wildcard+credentials not detected")
	}
	if hasRule("cors-wildcard-credentials", []walk.File{safe}, ".") {
		t.Error("precision miss: fired on an explicit origin allowlist")
	}
	if hasRule("cors-wildcard-credentials", []walk.File{wildOnly}, ".") {
		t.Error("precision miss: fired on wildcard without credentials")
	}
}

func TestCORSReversedOrder(t *testing.T) {
	// credentials before origin must still be caught (order-independent)
	vuln := mk("main.py", ".py", `CORSMiddleware(allow_credentials=True, allow_origins=["*"])`)
	if !hasRule("cors-wildcard-credentials", []walk.File{vuln}, ".") {
		t.Error("recall miss: reversed-order CORS misconfig not detected")
	}
}

func TestDangerouslySetInnerHTML(t *testing.T) {
	vuln := mk("Post.tsx", ".tsx", `<div dangerouslySetInnerHTML={{ __html: post.body }} />`)
	sanitized := mk("Post.tsx", ".tsx", `<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(post.body) }} />`)
	constant := mk("Post.tsx", ".tsx", `<div dangerouslySetInnerHTML={{ __html: '<b>Loading</b>' }} />`)

	if !hasRule("react-dangerous-html", []walk.File{vuln}, ".") {
		t.Error("recall miss: unsanitized dangerouslySetInnerHTML not detected")
	}
	if hasRule("react-dangerous-html", []walk.File{sanitized}, ".") {
		t.Error("precision miss: fired on a DOMPurify-sanitized value")
	}
	if hasRule("react-dangerous-html", []walk.File{constant}, ".") {
		t.Error("precision miss: fired on a constant string literal")
	}
}

func TestSupabaseServiceRoleClient(t *testing.T) {
	vuln := mk("lib/db.ts", ".ts", `export const admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)`)
	safe := mk("lib/db.ts", ".ts", `export const db = createClient(url, process.env.SUPABASE_ANON_KEY)`)

	if !hasRule("supabase-service-role-client", []walk.File{vuln}, ".") {
		t.Error("recall miss: service_role key in client code not detected")
	}
	if hasRule("supabase-service-role-client", []walk.File{safe}, ".") {
		t.Error("precision miss: fired on the anon key")
	}
}

func TestSupabaseMissingRLS(t *testing.T) {
	missing := mk("supabase/migrations/001.sql", ".sql",
		`create table public.notes (id uuid primary key, owner uuid, body text);`)
	enabled := mk("supabase/migrations/002.sql", ".sql",
		`create table public.notes (id uuid primary key, owner uuid, body text);
alter table public.notes enable row level security;
create policy p on public.notes for all using (auth.uid() = owner);`)
	disabled := mk("supabase/migrations/003.sql", ".sql",
		`alter table public.secrets disable row level security;`)

	if !hasRule("supabase-missing-rls", []walk.File{missing}, ".") {
		t.Error("recall miss: table without RLS not detected")
	}
	if hasRule("supabase-missing-rls", []walk.File{enabled}, ".") {
		t.Error("precision miss: fired on a table that enables RLS")
	}
	if !hasRule("supabase-rls-disabled", []walk.File{disabled}, ".") {
		t.Error("recall miss: explicit DISABLE RLS not detected")
	}
}

func TestRLSOnlyFiresForSupabaseProjects(t *testing.T) {
	// same CREATE TABLE, but in a plain Postgres/Prisma project with no Supabase
	// signal anywhere -> must NOT fire (those apps do authz in application code)
	plain := mk("db/schema.sql", ".sql",
		`create table users (id serial primary key, email text, password_hash text);`)
	if hasRule("supabase-missing-rls", []walk.File{plain}, ".") {
		t.Error("false positive: RLS rule fired on a non-Supabase project")
	}

	// add a Supabase signal (client import) and the same schema should now flag
	client := mk("lib/db.ts", ".ts", `import { createClient } from '@supabase/supabase-js'`)
	sql := mk("db/schema.sql", ".sql", `create table public.notes (id uuid primary key);`)
	if !hasRule("supabase-missing-rls", []walk.File{client, sql}, ".") {
		t.Error("recall miss: RLS rule should fire once Supabase is detected")
	}
}

func TestSupabaseRLSAcrossFiles(t *testing.T) {
	// table created in one migration, RLS enabled in a later one -> not a finding
	create := mk("supabase/migrations/001_create.sql", ".sql",
		`create table public.notes (id uuid primary key);`)
	enable := mk("supabase/migrations/002_rls.sql", ".sql",
		`alter table public.notes enable row level security;`)
	if hasRule("supabase-missing-rls", []walk.File{create, enable}, ".") {
		t.Error("precision miss: RLS enabled in a separate migration should clear the finding")
	}
}

func TestMissingRouteAuth(t *testing.T) {
	vuln := mk("pages/api/users.ts", ".ts",
		`export default async function handler(req, res){ const u = await prisma.user.findMany(); res.json(u) }`)
	safe := mk("pages/api/users.ts", ".ts",
		`export default async function handler(req, res){ const s = await getServerSession(req); if(!s) return res.status(401).end(); const u = await prisma.user.findMany(); res.json(u) }`)
	nonRoute := mk("lib/users.ts", ".ts",
		`export async function all(){ return prisma.user.findMany() }`)

	if !hasRule("missing-route-auth", []walk.File{vuln}, ".") {
		t.Error("recall miss: unauthenticated API route not detected")
	}
	if hasRule("missing-route-auth", []walk.File{safe}, ".") {
		t.Error("precision miss: fired on a route with getServerSession")
	}
	if hasRule("missing-route-auth", []walk.File{nonRoute}, ".") {
		t.Error("precision miss: fired on a non-route helper file")
	}
}

func TestEnvNotGitignored(t *testing.T) {
	// filesystem-based: build a temp project with a .env and vary .gitignore
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("SECRET=x"), 0o600); err != nil {
		t.Fatal(err)
	}
	envFile := walk.File{Path: ".env", Name: ".env", Ext: ".env", Content: []byte("SECRET=x")}

	// no .gitignore at all -> finding
	if !hasRule("env-not-gitignored", []walk.File{envFile}, dir) {
		t.Error("recall miss: .env with no .gitignore not flagged")
	}

	// .gitignore that covers .env -> no finding
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("node_modules\n.env\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if hasRule("env-not-gitignored", []walk.File{envFile}, dir) {
		t.Error("precision miss: flagged .env even though .gitignore covers it")
	}
}
