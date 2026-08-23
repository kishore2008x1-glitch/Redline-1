// api/scan.js
// Vercel Serverless Function (Node runtime). Fully self-contained — no
// cross-file require(), no npm dependencies, no API key.
// - GitHub's REST API allows unauthenticated read access to public repos (60 req/hr per IP).
// - Everything else is local pattern matching, defined right here.

const SEVERITY = { CRITICAL: 'critical', WARNING: 'warning', INFO: 'info' };

// ---------- rule engine helpers ----------
function findAll(regex, text) {
  const out = [];
  const re = new RegExp(regex.source, regex.flags.includes('g') ? regex.flags : regex.flags + 'g');
  let m;
  while ((m = re.exec(text)) !== null) {
    out.push({ index: m.index, match: m[0], groups: m.slice(1) });
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  return out;
}

function lineOf(text, index) {
  return text.slice(0, index).split('\n').length;
}

function lineText(text, index) {
  const start = text.lastIndexOf('\n', index) + 1;
  let end = text.indexOf('\n', index);
  if (end === -1) end = text.length;
  return text.slice(start, end).trim().slice(0, 160);
}

function redactSecret(snippet) {
  return snippet.replace(/([A-Za-z0-9_-]{6})[A-Za-z0-9_-]{6,}/g, (full, keep) => {
    if (/^(sk_live|sk_test|AKIA|AIza|eyJ)/.test(full) || full.length > 24) {
      return keep + '…redacted…';
    }
    return full;
  });
}

const SECRET_RULES = [
  { name: 'Stripe live secret key', re: /sk_live_[0-9a-zA-Z]{10,}/, severity: SEVERITY.CRITICAL },
  { name: 'Stripe test secret key', re: /sk_test_[0-9a-zA-Z]{10,}/, severity: SEVERITY.WARNING },
  { name: 'AWS access key ID', re: /AKIA[0-9A-Z]{16}/, severity: SEVERITY.CRITICAL },
  { name: 'Google API key', re: /AIza[0-9A-Za-z-_]{35}/, severity: SEVERITY.CRITICAL },
  { name: 'Slack token', re: /xox[baprs]-[0-9a-zA-Z-]{10,}/, severity: SEVERITY.CRITICAL },
  { name: 'Private key block', re: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/, severity: SEVERITY.CRITICAL },
  {
    name: 'Supabase / JWT-style service key',
    re: /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/,
    severity: SEVERITY.CRITICAL,
    guard: (snippet) => !/process\.env/.test(snippet),
  },
  {
    name: 'Generic hardcoded secret',
    re: /(api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret|password)\s*[:=]\s*['"`][A-Za-z0-9\-_/+=]{16,}['"`]/i,
    severity: SEVERITY.WARNING,
    guard: (snippet) => !/process\.env|import\.meta\.env|__PLACEHOLDER__|xxxx|your[_-]?key/i.test(snippet),
  },
];

const SENSITIVE_ROUTE = /\b(app|router)\.(get|post|put|patch|delete)\s*\(\s*['"`](\/[^'"`]*)?(checkout|payment|charge|admin|delete|withdraw|transfer|refund|order|subscribe)[^'"`]*['"`]/i;
const AUTH_KEYWORDS = /(requireAuth|isAuthenticated|verifyToken|authMiddleware|ensureLoggedIn|passport\.authenticate|req\.user\b|session\.user\b|getServerSession|auth\(\)|withAuth|checkAuth)/;
const CLIENT_TRUST_VARS = /\b(?:const|let|var)\s*\{\s*[^{}\n]*\b(amount|price|total|cost|quantity|role|isAdmin|admin)\b[^{}\n]*\}\s*=\s*req\.body/;
const RECOMPUTE_KEYWORDS = /(calculatePrice|getPrice|computeTotal|priceFor|lookupPrice|server[_-]?side)/i;

function scanText(filename, text) {
  const findings = [];

  for (const rule of SECRET_RULES) {
    for (const hit of findAll(rule.re, text)) {
      const snippet = lineText(text, hit.index);
      if (rule.guard && !rule.guard(snippet)) continue;
      findings.push({
        severity: rule.severity,
        ruleId: 'secret-exposure',
        title: rule.name + ' exposed in source',
        message: `A ${rule.name.toLowerCase()} appears to be hardcoded directly in the file instead of loaded from an environment variable.`,
        file: filename,
        line: lineOf(text, hit.index),
        snippet: redactSecret(snippet),
      });
    }
  }

  for (const hit of findAll(/Access-Control-Allow-Origin['"]?\s*[:=]\s*['"]\*['"]|cors\(\s*\{\s*origin\s*:\s*['"]\*['"]/i, text)) {
    findings.push({
      severity: SEVERITY.WARNING,
      ruleId: 'cors-wildcard',
      title: 'CORS allows any origin',
      message: 'This endpoint sets Access-Control-Allow-Origin to "*", letting any website make authenticated requests to it on a user\'s behalf.',
      file: filename,
      line: lineOf(text, hit.index),
      snippet: lineText(text, hit.index),
    });
  }

  for (const hit of findAll(/\beval\s*\(|new\s+Function\s*\(/, text)) {
    findings.push({
      severity: SEVERITY.WARNING,
      ruleId: 'dynamic-eval',
      title: 'Dynamic code execution',
      message: '`eval` or `new Function` executes a string as code. If any part of that string comes from user input, it\'s a direct route to remote code execution.',
      file: filename,
      line: lineOf(text, hit.index),
      snippet: lineText(text, hit.index),
    });
  }

  for (const hit of findAll(/\.(query|execute)\s*\(\s*[`"'][^`"']*\$\{[^}]+\}[^`"']*[`"']/, text)) {
    findings.push({
      severity: SEVERITY.CRITICAL,
      ruleId: 'sql-injection',
      title: 'SQL query built with string interpolation',
      message: 'User-influenced values appear to be interpolated directly into a SQL string rather than passed as bound parameters — classic SQL injection shape.',
      file: filename,
      line: lineOf(text, hit.index),
      snippet: lineText(text, hit.index),
    });
  }

  for (const hit of findAll(SENSITIVE_ROUTE, text)) {
    const windowText = text.slice(hit.index, hit.index + 500);
    if (!AUTH_KEYWORDS.test(windowText)) {
      findings.push({
        severity: SEVERITY.CRITICAL,
        ruleId: 'missing-auth',
        title: 'Sensitive route with no visible auth check',
        message: 'This route touches payments, admin actions, or account data, but no auth/session check (e.g. req.user, requireAuth) appears nearby — it may be callable by anyone.',
        file: filename,
        line: lineOf(text, hit.index),
        snippet: lineText(text, hit.index),
      });
    }
  }

  for (const hit of findAll(CLIENT_TRUST_VARS, text)) {
    const windowText = text.slice(hit.index, hit.index + 400);
    if (!RECOMPUTE_KEYWORDS.test(windowText)) {
      findings.push({
        severity: SEVERITY.WARNING,
        ruleId: 'trusting-client-input',
        title: 'Price, role, or quantity trusted from the client',
        message: 'A value like amount/price/role is read straight from req.body and used without being recalculated or checked server-side — a client can send whatever it wants.',
        file: filename,
        line: lineOf(text, hit.index),
        snippet: lineText(text, hit.index),
      });
    }
  }

  const hasWebhook = /['"`]\/[^'"`]*webhook[^'"`]*['"`]/i.test(text);
  const hasRateLimit = /rate[-_]?limit|express-rate-limit|@upstash\/ratelimit/i.test(text);
  if (hasWebhook && !hasRateLimit) {
    const hit = findAll(/['"`]\/[^'"`]*webhook[^'"`]*['"`]/i, text)[0];
    findings.push({
      severity: SEVERITY.INFO,
      ruleId: 'no-rate-limit',
      title: 'Public endpoint has no rate limiting',
      message: 'A webhook/public route was found with no rate-limiting middleware detected in this file, leaving it open to abuse or flooding.',
      file: filename,
      line: lineOf(text, hit.index),
      snippet: lineText(text, hit.index),
    });
  }

  if (/(^|\/)\.env(\..+)?$/.test(filename) && text.trim().length > 0) {
    findings.push({
      severity: SEVERITY.CRITICAL,
      ruleId: 'env-committed',
      title: '.env file committed to the repo',
      message: 'An environment file with real-looking values is present in the repository. If this was pushed to a public repo, every key in it should be rotated.',
      file: filename,
      line: 1,
      snippet: lineText(text, 0),
    });
  }

  return findings;
}

// ---------- GitHub fetch helpers (repo mode) ----------
const SCANNABLE_EXT = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py', '.env', '.example']);
const SKIP_PATH = /(^|\/)(node_modules|\.git|dist|build|\.next|vendor|coverage)(\/|$)/;
const SKIP_FILE = /\.(min\.js|lock|map|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|pdf)$/i;
const MAX_FILES = 25;
const MAX_TOTAL_BYTES = 450000;
const MAX_SINGLE_FILE_BYTES = 120000;

function parseGithubUrl(raw) {
  let url;
  try {
    url = new URL(raw.trim());
  } catch (e) {
    return null;
  }
  if (!/(^|\.)github\.com$/.test(url.hostname)) return null;
  const parts = url.pathname.split('/').filter(Boolean);
  if (parts.length < 2) return null;
  const owner = parts[0];
  const repo = parts[1].replace(/\.git$/, '');
  let branch = null;
  if (parts[2] === 'tree' && parts[3]) branch = decodeURIComponent(parts[3]);
  return { owner, repo, branch };
}

async function githubJson(url) {
  const r = await fetch(url, {
    headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'redline-scanner-prototype' },
  });
  if (r.status === 403) {
    let body = {};
    try { body = await r.json(); } catch (e) {}
    const err = new Error(body.message || 'GitHub API rate limit reached');
    err.code = 'RATE_LIMIT';
    throw err;
  }
  if (r.status === 404) {
    const err = new Error('Repository not found or private');
    err.code = 'NOT_FOUND';
    throw err;
  }
  if (!r.ok) {
    const err = new Error('GitHub API error (' + r.status + ')');
    err.code = 'GITHUB_ERROR';
    throw err;
  }
  return r.json();
}

function pickFiles(tree) {
  const candidates = tree.filter((entry) => {
    if (entry.type !== 'blob') return false;
    if (SKIP_PATH.test(entry.path)) return false;
    if (SKIP_FILE.test(entry.path)) return false;
    const ext = entry.path.includes('.') ? entry.path.slice(entry.path.lastIndexOf('.')) : '';
    const base = entry.path.split('/').pop();
    if (base.startsWith('.env')) return true;
    if (!SCANNABLE_EXT.has(ext)) return false;
    if (entry.size && entry.size > MAX_SINGLE_FILE_BYTES) return false;
    return true;
  });

  const priorityHint = /(route|checkout|payment|webhook|api|admin|auth|server|\.env)/i;
  candidates.sort((a, b) => {
    const pa = priorityHint.test(a.path) ? 0 : 1;
    const pb = priorityHint.test(b.path) ? 0 : 1;
    if (pa !== pb) return pa - pb;
    return (a.size || 0) - (b.size || 0);
  });

  const selected = [];
  let totalBytes = 0;
  for (const entry of candidates) {
    if (selected.length >= MAX_FILES) break;
    const size = entry.size || 0;
    if (totalBytes + size > MAX_TOTAL_BYTES) continue;
    selected.push(entry);
    totalBytes += size;
  }
  return selected;
}

async function fetchRaw(owner, repo, branch, path) {
  const encodedPath = path.split('/').map(encodeURIComponent).join('/');
  const url = 'https://raw.githubusercontent.com/' + owner + '/' + repo + '/' + encodeURIComponent(branch) + '/' + encodedPath;
  const r = await fetch(url);
  if (!r.ok) return null;
  return r.text();
}

function summarize(findings) {
  const summary = { critical: 0, warning: 0, info: 0 };
  for (const f of findings) summary[f.severity]++;
  return summary;
}

const severityRank = { critical: 0, warning: 1, info: 2 };

// ---------- handler ----------
module.exports = async function handler(req, res) {
  try {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') { res.status(204).end(); return; }
    if (req.method !== 'POST') { res.status(405).json({ error: 'Use POST' }); return; }

    let body = req.body;
    if (typeof body === 'string') {
      try { body = JSON.parse(body); } catch (e) { body = {}; }
    }
    if (!body || typeof body !== 'object') body = {};
    const mode = body.mode;
    const value = body.value;

    if (!value || typeof value !== 'string' || !value.trim()) {
      res.status(400).json({ error: 'Nothing to scan — paste some code or a GitHub repo URL.' });
      return;
    }

    if (mode === 'code') {
      const text = value.slice(0, MAX_SINGLE_FILE_BYTES);
      const findings = scanText('pasted-code', text);
      findings.sort((a, b) => severityRank[a.severity] - severityRank[b.severity]);
      res.status(200).json({
        target: 'Pasted code',
        filesScanned: 1,
        findings,
        summary: summarize(findings),
      });
      return;
    }

    if (mode === 'repo') {
      const parsed = parseGithubUrl(value);
      if (!parsed) {
        res.status(400).json({ error: 'That doesn\'t look like a GitHub repo URL, e.g. https://github.com/owner/repo' });
        return;
      }
      const owner = parsed.owner;
      const repo = parsed.repo;
      let branch = parsed.branch;

      try {
        if (!branch) {
          const repoMeta = await githubJson('https://api.github.com/repos/' + owner + '/' + repo);
          branch = repoMeta.default_branch;
        }
        const treeData = await githubJson(
          'https://api.github.com/repos/' + owner + '/' + repo + '/git/trees/' + encodeURIComponent(branch) + '?recursive=1'
        );
        const files = pickFiles(treeData.tree || []);
        if (files.length === 0) {
          res.status(200).json({
            target: owner + '/' + repo,
            filesScanned: 0,
            findings: [],
            summary: { critical: 0, warning: 0, info: 0 },
            note: 'No JS/TS/Python files matched — nothing scanned.',
          });
          return;
        }

        const contents = await Promise.all(
          files.map((f) => fetchRaw(owner, repo, branch, f.path).catch(() => null))
        );

        let findings = [];
        let scanned = 0;
        contents.forEach((text, i) => {
          if (text == null) return;
          scanned++;
          findings = findings.concat(scanText(files[i].path, text));
        });
        findings.sort((a, b) => severityRank[a.severity] - severityRank[b.severity]);

        res.status(200).json({
          target: owner + '/' + repo,
          branch,
          filesScanned: scanned,
          findings,
          summary: summarize(findings),
        });
        return;
      } catch (err) {
        if (err.code === 'RATE_LIMIT') {
          res.status(429).json({ error: 'GitHub\'s free API rate limit was hit for this server. Try again in a few minutes, or paste code directly instead.' });
          return;
        }
        if (err.code === 'NOT_FOUND') {
          res.status(404).json({ error: 'Repo not found — check the URL, and note only public repos can be scanned in this prototype.' });
          return;
        }
        res.status(500).json({ error: 'Scan failed: ' + (err && err.message ? err.message : String(err)) });
        return;
      }
    }

    res.status(400).json({ error: 'mode must be "code" or "repo"' });
  } catch (outerErr) {
    // Last-resort guard: whatever happens, always return valid JSON, never let
    // the platform's own crash page reach the frontend.
    try {
      res.status(500).json({ error: 'Unexpected server error: ' + (outerErr && outerErr.message ? outerErr.message : String(outerErr)) });
    } catch (e) {
      res.end('{"error":"Unexpected server error"}');
    }
  }
};
