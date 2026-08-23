# Redline — working prototype

A real (not scripted) full-stack prototype: static frontend + a Vercel
serverless function that actually scans code. No paid API, no API key.

## How it works

- **Frontend** (`index.html`) — marketing page plus a live scanner UI. You can
  paste code directly, or give it a public GitHub repo URL.
- **Backend** (`api/scan.js`) — a Vercel serverless function that:
  - For pasted code: runs the rule engine on it directly.
  - For a repo URL: calls GitHub's free public REST API (no auth needed,
    60 requests/hour per IP) to list the repo's file tree, pulls up to 25
    JS/TS/Python files (~450KB total budget), and scans each one.
- **Rule engine** (`lib/rules.js`) — pure regex/pattern matching, zero
  external calls. Detects: hardcoded secrets (Stripe, AWS, Google, Slack,
  private keys, JWT-style service keys, generic secret assignments), CORS
  wildcards, `eval`/`new Function`, string-interpolated SQL, sensitive
  routes with no nearby auth check, client-trusted price/role/amount
  values, missing rate limiting on webhook routes, and committed `.env`
  files.

This is genuinely free to run: GitHub's public API needs no key, and
Vercel's Hobby tier covers a static site + one serverless function.

## Deploy

```bash
npm i -g vercel   # if you don't have it
cd redline
vercel             # first deploy, follow prompts
vercel --prod       # promote to production
```

No environment variables required.

## Known limits (prototype, not production)

- Pattern matching means false positives/negatives — it's a heuristic
  engine, not a real SAST tool.
- GitHub's unauthenticated rate limit (60 req/hr/IP) means heavy repo-mode
  traffic will start failing until it resets; the API returns a clear
  error in that case.
- Only public repos can be scanned (no OAuth flow in this prototype).
- Large repos are capped at 25 files / ~450KB scanned, prioritizing files
  whose names suggest routes, auth, payments, or env config.
