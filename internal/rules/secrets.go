package rules

import "github.com/NotChaosuu/vibecheck/internal/model"

func secretRules() []Rule {
	allow := reList(
		`(?i)EXAMPLE`,
		`(?i)your[-_ ]?(api|secret|access|key)`,
		`(?i)xxxx+`,
		`(?i)placeholder`,
		`(?i)changeme`,
		`(?i)dummy`,
		`<[^>]+>`,
	)

	return []Rule{
		{
			ID: "secret-aws-access-key", Title: "Hardcoded AWS access key ID",
			Severity: model.Critical, Confidence: model.Confirmed,
			OWASP:   "A07:2021 Identification & Authentication Failures",
			Detail:  "An AWS access key ID (AKIA...) is committed in source. Anyone with the repo can use it.",
			Fix:     "Move it to a server-only env var and rotate the key in the AWS console.",
			Pattern: mustRE(`\bAKIA[0-9A-Z]{16}\b`), Allow: allow,
		},
		{
			ID: "secret-google-api-key", Title: "Hardcoded Google API key",
			Severity: model.High, Confidence: model.Confirmed,
			OWASP:   "A07:2021 Identification & Authentication Failures",
			Detail:  "A Google API key (AIza...) is hardcoded. Depending on scope it can be abused for billed API calls.",
			Fix:     "Restrict the key by referrer/IP, move it out of source, and rotate it.",
			Pattern: mustRE(`\bAIza[0-9A-Za-z\-_]{35}\b`), Allow: allow,
		},
		{
			ID: "secret-stripe-secret-key", Title: "Hardcoded Stripe secret key",
			Severity: model.Critical, Confidence: model.Confirmed,
			OWASP:   "A07:2021 Identification & Authentication Failures",
			Detail:  "A Stripe secret/restricted key (sk_live_ / rk_live_) is in source. This can move real money.",
			Fix:     "Move it to a server-only env var and roll the key in the Stripe dashboard.",
			Pattern: mustRE(`\b(sk|rk)_live_[0-9a-zA-Z]{20,}\b`), Allow: allow,
		},
		{
			ID: "secret-github-token", Title: "Hardcoded GitHub token",
			Severity: model.Critical, Confidence: model.Confirmed,
			OWASP:   "A07:2021 Identification & Authentication Failures",
			Detail:  "A GitHub personal access token (ghp_ / github_pat_) is committed. It can read/write your repos.",
			Fix:     "Revoke the token on GitHub and load it from an env var instead.",
			Pattern: mustRE(`\b(ghp_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{22,})\b`), Allow: allow,
		},
		{
			ID: "secret-openai-key", Title: "Hardcoded OpenAI API key",
			Severity: model.High, Confidence: model.Confirmed,
			OWASP:   "A07:2021 Identification & Authentication Failures",
			Detail:  "An OpenAI API key is hardcoded. It bills to your account and often ends up shipped in frontend code.",
			Fix:     "Move the call server-side, read the key from an env var, and rotate it.",
			Pattern: mustRE(`\b(sk-proj-[A-Za-z0-9_\-]{40,}|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})\b`), Allow: allow,
		},
		{
			ID: "secret-anthropic-key", Title: "Hardcoded Anthropic API key",
			Severity: model.High, Confidence: model.Confirmed,
			OWASP:   "A07:2021 Identification & Authentication Failures",
			Detail:  "An Anthropic API key (sk-ant-...) is hardcoded and bills to your account.",
			Fix:     "Move the call server-side, read from an env var, and rotate the key.",
			Pattern: mustRE(`\bsk-ant-[A-Za-z0-9_\-]{20,}\b`), Allow: allow,
		},
		{
			ID: "secret-slack-token", Title: "Hardcoded Slack token",
			Severity: model.High, Confidence: model.Confirmed,
			OWASP:   "A07:2021 Identification & Authentication Failures",
			Detail:  "A Slack token (xox...) is committed. It can read and post to the workspace.",
			Fix:     "Revoke it in Slack and load it from an env var.",
			Pattern: mustRE(`\bxox[baprs]-[0-9A-Za-z\-]{10,}\b`), Allow: allow,
		},
		{
			ID: "secret-private-key", Title: "Committed private key",
			Severity: model.Critical, Confidence: model.Confirmed,
			OWASP:   "A02:2021 Cryptographic Failures",
			Detail:  "A PEM private key block is committed in source.",
			Fix:     "Remove the key from the repo, rotate it, and load it from a secret store.",
			Pattern: mustRE(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`), Allow: allow,
		},
	}
}
