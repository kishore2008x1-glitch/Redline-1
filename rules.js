// lib/rules.js
// Redline's static analysis engine. Pure pattern-matching over source text —
// no external AI calls, so it costs nothing to run and has no API key to manage.
// Every rule returns {severity, rule, message, index} matches for a given file's text;
// the caller (api/scan.js) turns `index` into a line number and snippet.

const SEVERITY = { CRITICAL: 'critical', WARNING: 'warning', INFO: 'info' };

// ---------- helpers ----------
function findAll(regex, text) {
  const out = [];
  const re = new RegExp(regex.source, regex.flags.includes('g') ? regex.flags : regex.flags + 'g');
  let m;
  while ((m = re.exec(text)) !== null) {
    out.push({ index: m.index, match: m[0], groups: m.slice(1) });
    if (m.index === re.lastIndex) re.lastIndex++; // avoid infinite loop on zero-width match
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
  // Never echo a full live-looking secret back in the report — show enough to identify it, mask the rest.
  return snippet.replace(/([A-Za-z0-9_\-]{6})[A-Za-z0-9_\-]{6,}/g, (full, keep) => {
    if (/^(sk_live|sk_test|AKIA|AIza|eyJ)/.test(full) || full.length > 24) {
      return keep + '…redacted…';
    }
    return full;
  });
}

// ---------- secret patterns ----------
const SECRET_RULES = [
  { name: 'Stripe live secret key', re: /sk_live_[0-9a-zA-Z]{10,}/, severity: SEVERITY.CRITICAL },
  { name: 'Stripe test secret key', re: /sk_test_[0-9a-zA-Z]{10,}/, severity: SEVERITY.WARNING },
  { name: 'AWS access key ID', re: /AKIA[0-9A-Z]{16}/, severity: SEVERITY.CRITICAL },
  { name: 'Google API key', re: /AIza[0-9A-Za-z\-_]{35}/, severity: SEVERITY.CRITICAL },
  { name: 'Slack token', re: /xox[baprs]-[0-9a-zA-Z-]{10,}/, severity: SEVERITY.CRITICAL },
  { name: 'Private key block', re: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/, severity: SEVERITY.CRITICAL },
  {
    name: 'Supabase / JWT-style service key',
    re: /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/,
    severity: SEVERITY.CRITICAL,
    // Only flag when it looks embedded as a literal, not something read from process.env
    guard: (snippet) => !/process\.env/.test(snippet),
  },
  {
    name: 'Generic hardcoded secret',
    re: /(api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret|password)\s*[:=]\s*['"`][A-Za-z0-9\-_/+=]{16,}['"`]/i,
    severity: SEVERITY.WARNING,
    guard: (snippet) => !/process\.env|import\.meta\.env|__PLACEHOLDER__|xxxx|your[_-]?key/i.test(snippet),
  },
];

// ---------- structural / logic patterns ----------
const SENSITIVE_ROUTE = /\b(app|router)\.(get|post|put|patch|delete)\s*\(\s*['"`](\/[^'"`]*)?(checkout|payment|charge|admin|delete|withdraw|transfer|refund|order|subscribe)[^'"`]*['"`]/i;
const AUTH_KEYWORDS = /(requireAuth|isAuthenticated|verifyToken|authMiddleware|ensureLoggedIn|passport\.authenticate|req\.user\b|session\.user\b|getServerSession|auth\(\)|withAuth|checkAuth)/;
const CLIENT_TRUST_VARS = /\b(?:const|let|var)\s*\{\s*[^{}\n]*\b(amount|price|total|cost|quantity|role|isAdmin|admin)\b[^{}\n]*\}\s*=\s*req\.body/;
const RECOMPUTE_KEYWORDS = /(calculatePrice|getPrice|computeTotal|priceFor|lookupPrice|server[_-]?side)/i;

function scanText(filename, text) {
  const findings = [];

  // 1. Secrets
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

  // 2. CORS wildcard
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

  // 3. eval / dynamic code execution
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

  // 4. SQL built with string interpolation
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

  // 5. Sensitive route with no nearby auth check (200-char window after the match)
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

  // 6. Client-supplied amount/role trusted without recompute
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

  // 7. Public/webhook route with no rate limiting anywhere in file
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

  // 8. .env-looking file scanned directly (repo mode passes filename through)
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

module.exports = { scanText, SEVERITY };
