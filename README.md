# Redline — working prototype

A real, mostly-free, full-stack prototype: static SPA frontend + three
self-contained Vercel serverless functions.

## Pages (client-side hash routing, single index.html)

- `#/` — **Chat** (default landing). Attach a file or paste code, get scanned
  for real, then ask follow-up questions — "how do I fix #2?", "is this
  actually exploitable?" — with full conversation context.
- `#/scan` — the detailed scanner: paste code, a public GitHub repo, or
  upload/drag multiple files at once. Grade badge (A–F), severity filters,
  copy/download report, local scan history, per-finding "Suggest fix (AI)".
- `#/rules` — all 21 detection rules in plain English
- `#/roadmap` — honest framing of what this is (pattern matching) vs. what a
  real product needs next
- `#/about` — the original marketing page

## Backend

### `api/scan.js` — the core scanner (100% free, no key needed)

21 pattern-based rules, zero external calls except GitHub's free public API
for repo mode (no key, 60 req/hr/IP). Always returns valid JSON.

### `api/chat.js` — the conversational scanner (needs a Gemini key for Q&A)

Runs the **same rule engine** as `scan.js` (duplicated on purpose — no
cross-file `require()`, so nothing can go missing on deploy) against any
attached file. That scan always runs, free, whether or not Gemini is
configured. Gemini is only used for:
- Free-form security/coding questions with no file attached
- Conversational answers grounded in that scan's findings ("fix #2", "is
  this real or a false positive")

**Without `GEMINI_API_KEY` set:** attaching a file still returns real
findings and a grade, formatted as plain text — you just can't ask
follow-ups, and a bare question with no file returns a clear message telling
you to configure the key or attach a file instead. Nothing crashes either way.

### `api/explain.js` — one-off AI fix suggestions (needs the same Gemini key)

The "Suggest fix (AI)" button on the `/scan` page's detailed report — sends
just that one finding's snippet to Gemini, only when clicked.

**Setup (optional — everything else works without it):**

```bash
vercel env add GEMINI_API_KEY
# paste your key when prompted — never put it in any file in this repo
vercel --prod
```

Get a key at [Google AI Studio](https://aistudio.google.com/apikey) (free
tier, no card). **If a key is ever pasted into a chat, doc, or public repo,
treat it as compromised and regenerate it there** — rotating a key is cheap;
a leaked live key is not.

Model used: `gemini-3.6-flash` by default — override with a `GEMINI_MODEL`
env var if Google moves the goalposts again (they deprecated `gemini-2.5-flash`
for new API keys mid-build here; if you hit a 404 saying a model "is no
longer available," that error tells you the exact replacement name to use).

Both AI endpoints share a crude in-memory rate limit (20 req/min per warm
serverless instance) to protect the free-tier quota; it resets on cold start
since there's no shared store in this prototype.

## Deploy

```bash
npm i -g vercel
cd redline
vercel --prod
```

Deploy the **whole folder** (`index.html`, `package.json`, `api/scan.js`,
`api/chat.js`, `api/explain.js` together) from inside `redline/` — don't drag
a single file into the dashboard, and don't replace files individually in an
existing repo; overwrite everything at once so nothing is left mismatched.

## Verified locally before shipping (no live browser available in this sandbox)

- `node --check` on all three API files — no syntax errors
- Full mock request/response run through `api/chat.js` and `api/explain.js`,
  including: no API key + file attached (graceful local-scan fallback), no
  key + no file (clear 501), malformed file object, empty body, GET request
- A realistic two-turn conversation simulated with the exact payload shape
  the frontend sends (file scan → follow-up question), confirming the
  request/response contract matches on both ends
- Sample vulnerable snippets (secrets, XSS, command injection, path
  traversal, Python deserialization) each correctly triggered their rule via
  `api/scan.js`; clean code produces zero false positives
- Every DOM id referenced by the frontend script exists in the HTML, the
  inline `<script>` passes `node --check`, and all major HTML tags balance
- **Not verified:** an actual live call to the Gemini API, and real-browser/
  real-device rendering — this sandbox has no network access and no browser.
  Test both after deploying; check Vercel's function logs if `/api/chat` or
  `/api/explain` error.

## Known limits (prototype, not production)

- Pattern matching, not a real SAST engine — findings are candidates to
  review, not proven vulnerabilities (a couple of the sample tests above
  show it erring toward false positives over false negatives, by design).
- GitHub's unauthenticated rate limit (60 req/hr/IP) will start failing
  under heavy repo-mode traffic.
- Only public repos can be scanned (no OAuth flow).
- Chat history lives in browser memory only — refreshing the page clears it;
  scan history on the `/scan` page persists via localStorage instead.
- Chat file attachments are capped at ~200KB to keep the free Gemini calls
  fast and cheap; the detailed `/scan` page's upload tab handles larger/
  multi-file scans without any AI involved.
