# vibecheck

**AI wrote your app. It also left the doors open.**

A static security scanner for AI-generated / "vibe-coded" web apps. Point it at your own repo and it grades the codebase, lists every finding with a file:line and a fix, and checks your dependencies against known vulnerabilities live. One binary, no runtime dependencies, nothing to install alongside it.

The angle: tools built by AI code generators fail in a predictable way. They scaffold a working feature and leave the security config at its insecure default — an open Firebase rule, a Supabase table with no row-level security, a `NEXT_PUBLIC_` var holding a real secret, a wildcard CORS with credentials. Generic scanners are dataflow engines that read application logic and mostly skip that declarative surface. vibecheck goes straight at it.

```
$ vibecheck ./my-app

  vibecheck  ./my-app

  Security grade:  F  (0/100)
  Findings:        4 critical  5 high
  Languages:       JavaScript, Python
  Frameworks:      Firebase, Flask, Supabase
  Files scanned:   7

  CONFIRMED (5)  structural, safe to act on
    CRIT     Subprocess spawned with shell=True
      api/app.py:6  [command-shell-true]
      fix:   Pass an argument list and drop shell=True.

    CRIT     Firebase rules allow public read/write
      firestore.rules:3  [firebase-rules-open]
      match /{document=**} { allow read, write: if true; }
      fix:   Replace `if true` with `request.auth != null` plus per-document ownership checks.

    CRIT     Hardcoded Stripe secret key
      server.js:5  [secret-stripe-secret-key]
      fix:   Move it to a server-only env var and roll the key in the Stripe dashboard.

    CRIT     Endpoint returns process environment
      server.js:6  [env-dump-endpoint]
      fix:   Remove the debug route. Never return environment variables to a client.

    HIGH     CORS allows any origin with credentials
      server.js:4  [cors-wildcard-credentials]
      fix:   Replace the wildcard with an explicit list of trusted origins.

  REVIEW (4)  heuristic, worth a look
    HIGH     Table created without Row Level Security
      supabase/migrations/001_init.sql:1  [supabase-missing-rls]
      fix:   alter table messages enable row level security; then add per-user policies.

  VULNERABLE DEPENDENCIES (2)  via OSV.dev
    HIGH     jinja2@2.4.1 (PyPI)
      PYSEC-2026-1475  Jinja sandbox breakout through indirect reference to format method  fixed in 3.1.5
```

## The confirmed / review split

Every finding lands in one of two lanes, and the difference is the whole point:

- **CONFIRMED** — structural facts. A string starting with `sk_live_` is a Stripe key. `allow read, write: if true` is an open rule. `shell=True` runs a shell. These are safe to act on directly.
- **REVIEW** — heuristics. "This API route touches the database and has no auth guard" or "this SQL is built by interpolation" is *worth a look*, but whether it's actually exploitable needs your eyes. vibecheck says so instead of asserting it.

A scanner that cries wolf gets ignored. Keeping the two apart means a CONFIRMED finding actually means something.

## Install

```bash
go install github.com/NotChaosuu/vibecheck/cmd/vibecheck@latest
```

Or build from source:

```bash
git clone https://github.com/NotChaosuu/vibecheck.git
cd vibecheck
go build -o vibecheck ./cmd/vibecheck
```

Requires Go 1.22+. **Zero third-party dependencies** — the whole thing, including the OSV client, is standard library. A security tool that doesn't drag in a dependency tree of its own.

## Usage

```bash
vibecheck                       # scan the current directory
vibecheck ./my-app              # scan a specific path
vibecheck --json ./my-app       # JSON for CI
vibecheck -v ./my-app           # verbose: OWASP category + full explanation per finding
vibecheck --confirmed-only .    # hide the review lane, show only structural findings
vibecheck --min-severity high . # only critical + high
vibecheck --no-sca .            # skip the dependency check (code scan only)
vibecheck --offline .           # never touch the network
vibecheck --exit-code .         # exit non-zero on any confirmed critical/high (CI gate)
vibecheck --list                # print the rule catalogue
```

## What it catches

**Config / framework misconfig** (the part generic scanners miss)
- Firebase / Firestore / Storage rules in test mode (`allow read, write: if true`)
- Supabase tables created without Row Level Security, and explicit `disable row level security`
- Supabase `service_role` key used in client-reachable code
- Permissive CORS: wildcard origin with credentials, in Express / FastAPI / Flask, order-independent
- `NEXT_PUBLIC_` / `VITE_` / `REACT_APP_` variables holding a secret (they get inlined into the browser bundle)
- `.env` files not covered by `.gitignore`

**Secrets** — hardcoded AWS, Google, Stripe, GitHub, OpenAI, Anthropic, Slack keys and PEM private keys, matched on their distinctive prefixes to keep false positives near zero.

**Injection & unsafe sinks** — SQL built by string interpolation, `shell=True` and dynamic `exec`, `eval` on non-literal input, `pickle.loads` / unsafe `yaml.load`, `dangerouslySetInnerHTML` with an unsanitized value.

**Auth / crypto** — JWT `alg:none`, hardcoded JWT secret, signature verification disabled, TLS verification turned off, weak hashes (MD5/SHA1), debug mode left on, a route that returns `process.env`, API routes touching data with no auth guard.

**Vulnerable dependencies** — parses `package-lock.json`, `yarn.lock`, `requirements.txt`, `poetry.lock`, `Pipfile.lock`, and `go.mod`, then checks every resolved version against [OSV.dev](https://osv.dev) live. Because it queries at scan time, there's no local vulnerability database to keep updated — it always knows about the latest advisories, including recent supply-chain incidents.

See [`docs/rules.md`](docs/rules.md) for the full catalogue with severities and the confirmed/review split.

## Languages

JavaScript, TypeScript, React, Next.js, Python, Go, plus Firebase rules files and SQL migrations. Rules are data, so adding a language or a check is a matter of adding entries, not rewriting the engine.

## Scan your own code

vibecheck is a defensive tool for auditing code you own or are authorized to review. It reads files and, unless you pass `--offline` / `--no-sca`, sends only your dependency names and versions to OSV.dev — never your source. Point it at your side project before you ship it, or drop it into CI with `--exit-code` as a gate.

## How the grade works

The score starts at 100 and drops per finding, weighted by severity, with confirmed findings costing more than review ones and vulnerable dependencies counting like confirmed findings of their severity. A single confirmed critical caps the grade so a mostly-clean score can't paper over one real hole. A–F, where A means nothing confirmed came up.

## License

MIT. See [`LICENSE`](LICENSE).

---

**Chaosuu** | independent research on anti-bot systems and web/API security.

- GitHub: [NotChaosuu](https://github.com/NotChaosuu)
- Telegram: [t.me/chaosuudev](https://t.me/chaosuudev)
- X: [@NotChaosuu](https://x.com/NotChaosuu)
- Reddit: [u/NotChaosuu404](https://www.reddit.com/user/NotChaosuu404)

Other tools: [akamaixray](https://github.com/NotChaosuu/akamaixray) · [apkxray](https://github.com/NotChaosuu/apkxray) · [wafprobe](https://github.com/NotChaosuu/wafprobe) · [authmap](https://github.com/NotChaosuu/authmap) · [tlsprint](https://github.com/NotChaosuu/tlsprint)
