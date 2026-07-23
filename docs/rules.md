# Rule catalogue

Every check vibecheck ships, grouped by what it looks at. Each rule is either **confirmed** (structural, reported as fact) or **review** (heuristic, reported as worth-a-look). Run `vibecheck --list` for the same list from the binary.

## Secrets (confirmed)

Matched on distinctive prefixes so false positives stay near zero. Doc placeholders and env reads are suppressed.

| Rule | Severity | What it matches |
|---|---|---|
| `secret-aws-access-key` | critical | `AKIA` + 16 chars |
| `secret-stripe-secret-key` | critical | `sk_live_` / `rk_live_` |
| `secret-github-token` | critical | `ghp_` / `github_pat_` |
| `secret-private-key` | critical | PEM private key block |
| `secret-google-api-key` | high | `AIza` + 35 chars |
| `secret-openai-key` | high | `sk-proj-…` / legacy `sk-…T3BlbkFJ…` |
| `secret-anthropic-key` | high | `sk-ant-…` |
| `secret-slack-token` | high | `xox[baprs]-…` |

## Config / framework misconfig

The declarative surface generic scanners skip.

| Rule | Severity | Confidence | What it flags |
|---|---|---|---|
| `firebase-rules-open` | critical | confirmed | `allow read, write: if true` / RTDB `".read": true` |
| `firebase-rules-any-authed` | high | review | `if request.auth != null` with no ownership check |
| `supabase-rls-disabled` | critical | confirmed | `alter table … disable row level security` |
| `supabase-missing-rls` | high | review | `create table` with no matching `enable row level security` |
| `supabase-service-role-client` | critical | review | `service_role` key used in client-reachable code |
| `cors-wildcard-credentials` | high | confirmed | wildcard origin + credentials (Express/FastAPI/Flask, order-independent) |
| `nextpublic-secret-name` | high | review | `NEXT_PUBLIC_` / `VITE_` / `REACT_APP_` var named like a secret |
| `env-dump-endpoint` | critical | confirmed | handler returns `process.env` |
| `env-not-gitignored` | high | review | `.env` present but not covered by `.gitignore` |
| `debug-mode-enabled` | high | review | `debug=True` (Flask/Django) |

## Injection & unsafe sinks

| Rule | Severity | Confidence | What it flags |
|---|---|---|---|
| `command-shell-true` | critical | confirmed | `subprocess(..., shell=True)` |
| `pickle-loads` | critical | confirmed | `pickle.load/loads` on untrusted data |
| `yaml-unsafe-load` | high | confirmed | `yaml.load` without SafeLoader / `yaml.unsafe_load` |
| `command-exec-dynamic` | high | review | `os.system` / `child_process.exec` from a dynamic string |
| `eval-dynamic-input` | high | review | JS `eval` / `new Function` on a non-literal |
| `python-eval-exec` | high | review | Python `eval` / `exec` on a non-literal |
| `sql-string-interpolation` | high | review | interpolation into a `.query()`/`.execute()`/`` sql` `` call |
| `sql-fstring-interpolation` | high | review | Python f-string SQL passed to `execute()` |
| `react-dangerous-html` | high | review | `dangerouslySetInnerHTML` with a non-constant, unsanitized value |
| `weak-hash` | medium | review | MD5 / SHA1 used for security |
| `open-redirect` | medium | review | redirect target taken straight from the request |
| `postmessage-wildcard-origin` | medium | confirmed | `postMessage(data, '*')` |

## Auth / crypto

| Rule | Severity | Confidence | What it flags |
|---|---|---|---|
| `jwt-alg-none` | critical | confirmed | JWT `alg` / `algorithms` set to `none` |
| `jwt-hardcoded-secret` | high | confirmed | `jwt.sign` / `jwt.encode` with a string-literal secret |
| `jwt-decode-no-verify` | high | review | `verify_signature: False` |
| `tls-verification-disabled` | high | confirmed | `InsecureSkipVerify: true`, `rejectUnauthorized: false`, `verify=False`, `CERT_NONE` |
| `missing-route-auth` | medium/high | review | API route runs a DB op with no auth guard (high if the path looks privileged) |

## Dependencies (via OSV.dev)

Resolved versions from `package-lock.json`, `yarn.lock`, `requirements.txt`, `poetry.lock`, `Pipfile.lock`, and `go.mod` are checked live against [OSV.dev](https://osv.dev). Severity comes from the advisory. No local database — the check is always current.

## Test files

Patterns that are normal in test code (disabling TLS to reach a self-signed local server, for example) are suppressed under `test/`, `tests/`, `__tests__/`, `spec/`, `e2e/`, `benchmark/`, `fixtures/`, `examples/`, and `*.test.*` / `*.spec.*` files. Secrets and config-file rules still apply everywhere — a leaked key in a fixture is still leaked.

## Adding a rule

Rules are Go structs in `internal/rules/`. A simple rule is a pattern plus a few allowlist suppressors:

```go
{
    ID: "my-rule", Title: "Short title",
    Severity: model.High, Confidence: model.Confirmed,
    OWASP:   "A03:2021 Injection",
    Detail:  "Why this is a problem.",
    Fix:     "One-line fix.",
    Pattern: mustRE(`the-pattern`),
    Allow:   reList(`suppressor-1`, `suppressor-2`),
}
```

Anything needing cross-line or structural logic goes in `internal/analyze/` as a function that returns findings. Every rule ships with a precision/recall test: it must fire on the vulnerable snippet and stay silent on the safe one.
