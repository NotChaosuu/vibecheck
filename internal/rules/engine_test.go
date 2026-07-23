package rules

import (
	"strings"
	"testing"

	"github.com/NotChaosuu/vibecheck/internal/walk"
)

func mkFile(name, ext, content string) walk.File {
	return walk.File{Path: name, Name: name, Ext: ext, Content: []byte(content)}
}

func fires(ruleID string, f walk.File) bool {
	for _, find := range Run([]walk.File{f}, All()) {
		if find.RuleID == ruleID {
			return true
		}
	}
	return false
}

// Each case asserts the rule FIRES on the vulnerable snippet and STAYS SILENT
// on the safe one. The safe half is the point: a false confirmed finding is
// what damages trust, so every rule earns its keep by not crying wolf.
func TestRulePrecisionAndRecall(t *testing.T) {
	longA := strings.Repeat("a", 40)
	cases := []struct {
		rule       string
		name, ext  string
		vuln, safe string
	}{
		{
			"secret-aws-access-key", "a.js", ".js",
			`const k = "AKIA` + strings.Repeat("A", 16) + `"`,
			`const k = process.env.AWS_ACCESS_KEY_ID`,
		},
		{
			"secret-google-api-key", "a.js", ".js",
			`const k = "AIza` + strings.Repeat("b", 35) + `"`,
			`const k = process.env.GOOGLE_API_KEY`,
		},
		{
			"secret-stripe-secret-key", "a.js", ".js",
			`const k = "sk_live_` + strings.Repeat("c", 24) + `"`,
			`const k = "pk_live_` + strings.Repeat("c", 24) + `"`, // publishable key is fine
		},
		{
			"secret-github-token", "a.js", ".js",
			`const t = "ghp_` + strings.Repeat("d", 36) + `"`,
			`const t = process.env.GITHUB_TOKEN`,
		},
		{
			"secret-openai-key", "a.js", ".js",
			`const k = "sk-proj-` + longA + `"`,
			`const k = process.env.OPENAI_API_KEY`,
		},
		{
			"secret-private-key", "a.pem", ".js",
			"-----BEGIN PRIVATE KEY-----",
			"const publicKey = loadPublicKey()",
		},
		{
			"secret-aws-access-key", "doc.js", ".js",
			`const k = "AKIA` + strings.Repeat("A", 16) + `"`,
			`const example = "AKIAIOSFODNN7EXAMPLE"`, // AWS's own doc placeholder
		},
		{
			"firebase-rules-open", "firestore.rules", ".rules",
			"allow read, write: if true;",
			"allow read: if false;",
		},
		{
			"firebase-rules-any-authed", "firestore.rules", ".rules",
			"allow read, write: if request.auth != null;",
			"allow read, write: if request.auth.uid == resource.data.owner;",
		},
		{
			"jwt-alg-none", "a.js", ".js",
			`jwt.verify(token, key, { algorithms: ['none'] })`,
			`jwt.verify(token, key, { algorithms: ['HS256'] })`,
		},
		{
			"jwt-hardcoded-secret", "a.js", ".js",
			`jwt.sign(payload, 'my-super-secret')`,
			`jwt.sign(payload, process.env.JWT_SECRET)`,
		},
		{
			"jwt-decode-no-verify", "a.py", ".py",
			`jwt.decode(token, options={"verify_signature": False})`,
			`jwt.decode(token, key, algorithms=["HS256"])`,
		},
		{
			"tls-verification-disabled", "a.go", ".go",
			`tls.Config{InsecureSkipVerify: true}`,
			`tls.Config{MinVersion: tls.VersionTLS12}`,
		},
		{
			"tls-verification-disabled", "a.py", ".py",
			`requests.get(url, verify=False)`,
			`requests.get(url, verify=True)`,
		},
		{
			"debug-mode-enabled", "a.py", ".py",
			`app.run(host="0.0.0.0", debug=True)`,
			`app.run(debug=os.environ.get("DEBUG") == "1")`,
		},
		{
			"env-dump-endpoint", "a.js", ".js",
			`app.get('/debug', (req, res) => res.json(process.env))`,
			`app.get('/config', (req, res) => res.json(publicConfig))`,
		},
		{
			"nextpublic-secret-name", "a.ts", ".ts",
			`const k = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY`,
			`const k = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY`,
		},
		{
			"postmessage-wildcard-origin", "a.js", ".js",
			`iframe.contentWindow.postMessage(token, '*')`,
			`iframe.contentWindow.postMessage(token, 'https://app.example.com')`,
		},
		{
			"sql-string-interpolation", "a.ts", ".ts",
			"db.query(`SELECT * FROM users WHERE id = ${userId}`)",
			"db.query('SELECT * FROM users WHERE id = $1', [userId])",
		},
		{
			"sql-fstring-interpolation", "a.py", ".py",
			`cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`,
			`cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`,
		},
		{
			"command-shell-true", "a.py", ".py",
			`subprocess.run(f"ping {host}", shell=True)`,
			`subprocess.run(["ping", host])`,
		},
		{
			"command-exec-dynamic", "a.py", ".py",
			`os.system("ping " + host)`,
			`subprocess.run(["ping", host])`,
		},
		{
			"eval-dynamic-input", "a.js", ".js",
			`const r = eval(userInput)`,
			`const r = JSON.parse(data)`,
		},
		{
			"python-eval-exec", "a.py", ".py",
			`result = eval(user_input)`,
			`result = ast.literal_eval(user_input)`,
		},
		{
			"pickle-loads", "a.py", ".py",
			`data = pickle.loads(request.data)`,
			`data = json.loads(request.data)`,
		},
		{
			"yaml-unsafe-load", "a.py", ".py",
			`cfg = yaml.load(stream)`,
			`cfg = yaml.safe_load(stream)`,
		},
		{
			"weak-hash", "a.py", ".py",
			`h = hashlib.md5(password).hexdigest()`,
			`h = hashlib.sha256(password).hexdigest()`,
		},
		{
			"open-redirect", "a.js", ".js",
			`res.redirect(req.query.next)`,
			`res.redirect('/dashboard')`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.rule+"/"+tc.name, func(t *testing.T) {
			if !fires(tc.rule, mkFile(tc.name, tc.ext, tc.vuln)) {
				t.Errorf("recall miss: %s did NOT fire on vulnerable snippet:\n  %s", tc.rule, tc.vuln)
			}
			if fires(tc.rule, mkFile(tc.name, tc.ext, tc.safe)) {
				t.Errorf("precision miss: %s DID fire on safe snippet (false positive):\n  %s", tc.rule, tc.safe)
			}
		})
	}
}

// A SQL keyword in prose is not a query. These must never fire the SQL rules.
func TestSQLProseNotFlagged(t *testing.T) {
	prose := []struct{ name, ext, code string }{
		{"a.ts", ".ts", "const msg = `Select the admins from the list: ${names.join(', ')}`"},
		{"a.jsx", ".jsx", "return <p>{`Update your settings before ${deadline}`}</p>"},
		{"a.py", ".py", `label = f"Delete from favorites? {item}"`},
	}
	for _, p := range prose {
		f := mkFile(p.name, p.ext, p.code)
		if fires("sql-string-interpolation", f) || fires("sql-fstring-interpolation", f) {
			t.Errorf("false positive: SQL rule fired on prose:\n  %s", p.code)
		}
	}
}

// TLS-disabled is normal in test code (self-signed local servers). It fires in
// app code but is suppressed under test/ paths.
func TestTLSDisabledSkippedInTests(t *testing.T) {
	appCode := mkFile("src/client.ts", ".ts", `const agent = new https.Agent({ rejectUnauthorized: false })`)
	if !fires("tls-verification-disabled", appCode) {
		t.Error("recall miss: TLS-disabled should fire in application code")
	}
	for _, p := range []string{"test/https.ts", "test/helpers/server.ts", "src/client.test.ts", "benchmark/index.ts"} {
		tf := mkFile(p, ".ts", `const agent = new https.Agent({ rejectUnauthorized: false })`)
		if fires("tls-verification-disabled", tf) {
			t.Errorf("false positive: TLS-disabled fired in test file %s", p)
		}
	}
}

// child_process.exec(var) must land on the command-injection rule (with the
// execFile/spawn fix), NOT on the eval rule (with the JSON.parse fix).
func TestEvalDoesNotClaimChildProcessExec(t *testing.T) {
	f := mkFile("a.js", ".js", `child_process.exec(userCmd)`)
	if fires("eval-dynamic-input", f) {
		t.Error("eval rule wrongly fired on child_process.exec (dotted method call)")
	}
	if !fires("command-exec-dynamic", f) {
		t.Error("command-exec-dynamic should fire on child_process.exec(var)")
	}

	// a JS regex .exec() is not code execution and must stay silent
	rx := mkFile("a.js", ".js", `const m = /ab+c/.exec(input)`)
	if fires("eval-dynamic-input", rx) || fires("command-exec-dynamic", rx) {
		t.Error("false positive: regex .exec() flagged as code/command execution")
	}

	// a method NAMED exec is a definition, not the Python builtin
	methodJS := mkFile("helper.ts", ".ts", `async exec(t, run) { return run(t); }`)
	if fires("eval-dynamic-input", methodJS) {
		t.Error("false positive: a JS method named exec flagged as eval")
	}
	methodPy := mkFile("helper.py", ".py", `    def exec(self, cmd):`)
	if fires("python-eval-exec", methodPy) {
		t.Error("false positive: a Python method definition named exec flagged")
	}
}
