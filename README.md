# Redline — working prototype

A real, free, full-stack prototype: static SPA frontend + one self-contained
Vercel serverless function. No paid API, no API key, no framework build step.

## Pages (client-side hash routing, single index.html)

- `#/` — marketing home, with a live "what it checks for" chip list
- `#/scan` — the actual scanner: paste code, point at a public GitHub repo,
  or upload/drag files. Real results, grade badge (A–F), severity filters,
  copy/download report, and a local (localStorage) recent-scans history.
- `#/rules` — all 21 detection rules in plain English, generated from the
  same list the scan page uses to render its "what it checks for" chips.
- `#/roadmap` — honest framing of what this prototype is (pattern matching)
  vs. what a real product needs next (verification, fixes, regression checks).

## Backend (`api/scan.js`)

One self-contained Vercel serverless function — no cross-file `require`,
so nothing can go missing between your machine and Vercel's build. It:

- Runs 21 pattern-based rules (secrets, SQL injection incl. Python and
  indirect forms, XSS incl. Flask template strings, command injection, path
  traversal, SSRF, missing auth incl. Python routes, IDOR, mass assignment,
  trusting client input, insecure deserialization, weak crypto/disabled TLS,
  debug mode, CORS wildcard, dynamic code execution, no rate limiting,
  committed `.env` files).
- For a GitHub URL: pulls the repo's file tree via GitHub's free public API
  (no key, 60 req/hr/IP) and scans up to 25 files (~450KB budget).
- For uploaded files: scans whatever the browser read client-side and sent
  up (25 files / ~600KB budget).
- Every branch is wrapped so it always returns valid JSON — even an
  unexpected error returns `{"error": "..."}` instead of Vercel's crash page.

## Deploy

```bash
npm i -g vercel
cd redline
vercel --prod
```

No environment variables required. Deploy the **whole folder** (`index.html`,
`package.json`, `api/scan.js` together) — the CLI run from inside `redline/`
is what keeps the structure intact; don't drag a single file into the
dashboard.

## Verified locally before shipping

- `node --check api/scan.js` — no syntax errors
- Full mock request/response run through the handler for `code`, `files`,
  and `repo` modes, plus edge cases (GET, missing body, malformed JSON, bad
  repo URL) — every path returns clean JSON, nothing throws
- Sample vulnerable snippets for XSS, command injection, path traversal, and
  Python deserialization each correctly triggered their rule
- Clean, properly-secured code produces zero findings (no false positives
  on the negative test case)
- Every DOM id referenced by the frontend script exists in the HTML; the
  inline `<script>` block passes `node --check`; all major tags balance

## Known limits (prototype, not production)

- Pattern matching, not a real SAST engine — it favors recall, so treat
  findings as candidates to review, not proven vulnerabilities.
- GitHub's unauthenticated rate limit (60 req/hr/IP) will start failing
  under heavy repo-mode traffic; the API returns a clear error when this
  happens.
- Only public repos can be scanned (no OAuth flow in this prototype).
- Scan history is stored in the visitor's own browser (localStorage) —
  nothing is persisted server-side, and nothing is shared between devices.
