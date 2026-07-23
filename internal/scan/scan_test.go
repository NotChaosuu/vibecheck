package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NotChaosuu/vibecheck/internal/model"
)

// write builds a file inside dir, creating parent directories as needed.
func write(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func ruleIDs(r *model.Result) map[string]bool {
	m := map[string]bool{}
	for _, f := range r.Findings {
		m[f.RuleID] = true
	}
	return m
}

// TestEndToEndVulnerableProject builds a realistic vibe-coded mess and asserts
// the scanner grades it F and catches the headline issues. Secret values are
// assembled by concatenation so no literal key is ever written to disk or lives
// in this source file.
func TestEndToEndVulnerableProject(t *testing.T) {
	dir := t.TempDir()

	stripeKey := "sk_live_" + strings.Repeat("a", 24)

	write(t, dir, "server.js", `
const express = require('express');
const cors = require('cors');
const app = express();
app.use(cors({ origin: '*', credentials: true }));
const stripe = require('stripe')('`+stripeKey+`');
app.get('/debug', (req, res) => res.json(process.env));
`)

	write(t, dir, "components/Post.jsx", `
export default function Post({ post }) {
  return <div dangerouslySetInnerHTML={{ __html: post.body }} />;
}
`)

	write(t, dir, "api/app.py", `
import subprocess, pickle
from flask import Flask
app = Flask(__name__)

def run(host):
    subprocess.run("ping " + host, shell=True)

def load(data):
    return pickle.loads(data)

app.run(host="0.0.0.0", debug=True)
`)

	write(t, dir, "firestore.rules", `
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} { allow read, write: if true; }
  }
}
`)

	write(t, dir, "supabase/migrations/001_init.sql", `
create table public.messages (id uuid primary key, user_id uuid, body text);
`)

	write(t, dir, ".env", "STRIPE_SECRET=whatever\nDB_PASSWORD=hunter2\n")
	// deliberately no .gitignore, so .env is exposed

	res, _ := Run(Options{Target: dir, Offline: true})
	if res == nil {
		t.Fatal("nil result")
	}

	if res.Grade != "F" {
		t.Errorf("expected grade F for this mess, got %s (score %d)", res.Grade, res.Score)
	}

	ids := ruleIDs(res)
	want := []string{
		"cors-wildcard-credentials",
		"secret-stripe-secret-key",
		"env-dump-endpoint",
		"react-dangerous-html",
		"command-shell-true",
		"pickle-loads",
		"debug-mode-enabled",
		"firebase-rules-open",
		"supabase-missing-rls",
		"env-not-gitignored",
	}
	for _, id := range want {
		if !ids[id] {
			t.Errorf("expected finding %q was not produced", id)
		}
	}

	// sanity: some confirmed findings exist
	confirmed := 0
	for _, f := range res.Findings {
		if f.Confidence == model.Confirmed {
			confirmed++
		}
	}
	if confirmed == 0 {
		t.Error("expected at least one confirmed finding")
	}
}

// TestCleanProjectScoresWell makes sure a tidy project doesn't get flagged to
// death. This is the precision guard at the project level.
func TestCleanProjectScoresWell(t *testing.T) {
	dir := t.TempDir()

	write(t, dir, "server.js", `
const express = require('express');
const cors = require('cors');
const app = express();
app.use(cors({ origin: ['https://app.example.com'], credentials: true }));
const key = process.env.STRIPE_SECRET_KEY;
`)
	write(t, dir, "components/Post.jsx", `
import DOMPurify from 'dompurify';
export default function Post({ post }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(post.body) }} />;
}
`)
	write(t, dir, "firestore.rules", `
match /users/{uid} {
  allow read, write: if request.auth != null && request.auth.uid == uid;
}
`)
	write(t, dir, "supabase/migrations/001_init.sql", `
create table public.messages (id uuid primary key, user_id uuid, body text);
alter table public.messages enable row level security;
create policy own on public.messages for all using (auth.uid() = user_id);
`)
	write(t, dir, ".gitignore", "node_modules\n.env\n")
	write(t, dir, ".env", "SECRET=x")

	res, _ := Run(Options{Target: dir, Offline: true})
	if res == nil {
		t.Fatal("nil result")
	}
	if res.Grade == "F" {
		t.Errorf("clean project should not be F, got score %d", res.Score)
	}
	// none of these should fire on the clean project
	for _, f := range res.Findings {
		switch f.RuleID {
		case "cors-wildcard-credentials", "react-dangerous-html", "firebase-rules-open",
			"supabase-missing-rls", "env-not-gitignored", "secret-stripe-secret-key":
			t.Errorf("false positive on clean project: %s at %s:%d", f.RuleID, f.File, f.Line)
		}
	}
}
