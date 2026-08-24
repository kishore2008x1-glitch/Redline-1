# Redline — working prototype

A real, free, full-stack prototype: static SPA frontend + one self-contained
Vercel serverless function. No paid API, no API key, no framework build step.

## Design system

The UI is re-skinned to the "Authkit" frosted-glass midnight system:
https://styles.refero.design/style/e80231a2-e4d6-406a-a2c9-2e6109679690

- Midnight Canvas background (#05060f) with a faint blueprint grid and a
  conic-gradient spotlight halo behind the hero
- Frosted-glass cards: translucent tint + hairline border + inset-frost/halo
  elevation instead of flat drop shadows
- Pill buttons (999px), 16px cards/modals, 6px inputs/badges, 9999px icon
  containers — per the system's radius families
- Space Grotesk (aeonikPro substitute) for the hero/section headings with
  the Skywash gradient fill; Inter (Untitled Sans substitute) for body/UI;
  JetBrains Mono (dotDigital substitute) for eyebrow labels and code
- Void Violet (#663af3) reserved for the single primary submit action
  ("Run scan") — the system's own doc reserves it for the auth-form Continue
  button; "Run scan" is this app's equivalent, and no other button uses it
- Severity colors (critical/warning/info/safe) are a deliberate functional
  exception to the "one accent" rule — pulled from the system's own
  secondary swatches (Ember Glow, Signal Blue, Deep Teal) rather than new hues

Note: I could not literally run the referenced `ui-ux-pro-max-skill` CLI/
plugin (no network access for `npm install`, no way to register a Claude
Code marketplace skill from inside a chat session) or fetch the design
tokens via API — no key was provided and this uses a public style-viewer
page, not an authenticated endpoint. I fetched the live style page directly
and hand-applied its documented tokens and component specs instead.

## Pages (client-side hash routing, single index.html)

- `#/` — marketing home, with a live "what it checks for" chip list
- `#/scan` — the actual scanner: paste code, point at a public GitHub repo,
  or upload/drag files. Real results, grade badge (A–F), severity filters,
  copy/download report, and a local (localStorage) recent-scans history.
- `#/rules` — all 21 detection rules in plain English
- `#/roadmap` — honest framing of what this prototype is (pattern matching)
  vs. what a real product needs next

## Backend (`api/scan.js`)

One self-contained Vercel serverless function — no cross-file `require`.
Runs 21 pattern-based rules (secrets, SQL injection incl. Python and
indirect forms, XSS incl. template strings, command injection, path
traversal, SSRF, missing auth incl. Python routes, IDOR, mass assignment,
trusting client input, insecure deserialization, weak crypto/disabled TLS,
debug mode, CORS wildcard, dynamic code execution, no rate limiting,
committed `.env` files). GitHub repo mode uses GitHub's free public API
(no key, 60 req/hr/IP). File-upload mode scans whatever the browser reads
client-side and sends up. Every branch returns valid JSON, even on error.

## Deploy

```bash
npm i -g vercel
cd redline
vercel --prod
```

No environment variables required. Deploy the whole folder together.

## Verified before shipping

- `node --check` on both the inline frontend script and the backend — no
  syntax errors
- All HTML tags balanced (div/section/span/button/form/style open==close)
- Every DOM id the script references exists in the HTML
- No leftover reference to any color from the old palette anywhere in the
  file — confirmed by grepping for the old hex values
- Backend re-tested end-to-end after the re-skin (re-skin only touched
  `index.html`; `api/scan.js` is byte-identical to the last verified version)

## Known limits (prototype, not production)

- Pattern matching, not a real SAST engine — treat findings as candidates
  to review, not proven vulnerabilities
- GitHub's unauthenticated rate limit (60 req/hr/IP) will start failing
  under heavy repo-mode traffic
- Only public repos can be scanned (no OAuth flow)
- Scan history lives in the visitor's own browser (localStorage) only
