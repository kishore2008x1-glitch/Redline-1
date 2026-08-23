// api/scan.js
// Vercel Serverless Function (Node runtime). Fully self-contained — no
// cross-file require(), no npm dependencies, no API key.
// - GitHub's REST API allows unauthenticated read access to public repos (60 req/hr per IP).
// - Everything else is local pattern matching, defined right here.

const SEVERITY = { CRITICAL: 'critical', WARNING: 'warning', INFO: 'info' };

// ---------- rule engine helpers ----------
function findAll(regex, text) {
  const out = [];
  const re = new RegExp(
    regex.source,
    regex.flags.includes('g') ? regex.flags : regex.flags + 'g'
  );

  let m;
  while ((m = re.exec(text)) !== null) {
    out.push({
      index: m.index,
      match: m[0],
      groups: m.slice(1)
    });

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
  return snippet.replace(
    /([A-Za-z0-9_-]{6})[A-Za-z0-9_-]{6,}/g,
    (full, keep) => {
      if (
        /^(sk_live|sk_test|AKIA|AIza|eyJ)/.test(full) ||
        full.length > 24
      ) {
        return keep + '…redacted…';
      }

      return full;
    }
  );
}

// ---------- secret detection ----------

const SECRET_RULES = [
  {
    name: 'Stripe live secret key',
    re: /sk_live_[0-9a-zA-Z]{10,}/,
    severity: SEVERITY.CRITICAL
  },

  {
    name: 'Stripe test secret key',
    re: /sk_test_[0-9a-zA-Z]{10,}/,
    severity: SEVERITY.WARNING
  },

  {
    name: 'AWS access key ID',
    re: /AKIA[0-9A-Z]{16}/,
    severity: SEVERITY.CRITICAL
  },

  {
    name: 'Google API key',
    re: /AIza[0-9A-Za-z-_]{35}/,
    severity: SEVERITY.CRITICAL
  },

  {
    name: 'Slack token',
    re: /xox[baprs]-[0-9a-zA-Z-]{10,}/,
    severity: SEVERITY.CRITICAL
  },

  {
    name: 'Private key block',
    re: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/,
    severity: SEVERITY.CRITICAL
  },

  {
    name: 'Supabase / JWT-style service key',
    re: /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/,
    severity: SEVERITY.CRITICAL,
    guard: (snippet) => !/process\.env/.test(snippet)
  },

  {
    name: 'Generic hardcoded secret',
    re: /(api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret|password)\s*[:=]\s*['"`][A-Za-z0-9\-_/+=]{16,}['"`]/i,
    severity: SEVERITY.WARNING,
    guard: (snippet) =>
      !/process\.env|import\.meta\.env|__PLACEHOLDER__|xxxx|your[_-]?key/i.test(
        snippet
      )
  }
];

const SENSITIVE_ROUTE =
  /\b(app|router)\.(get|post|put|patch|delete)\s*\(\s*['"`](\/[^'"`]*)?(checkout|payment|charge|admin|delete|withdraw|transfer|refund|order|subscribe)[^'"`]*['"`]/i;

const AUTH_KEYWORDS =
  /(requireAuth|isAuthenticated|verifyToken|authMiddleware|ensureLoggedIn|passport\.authenticate|req\.user\b|session\.user\b|getServerSession|auth\(\)|withAuth|checkAuth)/;

const CLIENT_TRUST_VARS =
  /\b(?:const|let|var)\s*\{\s*[^{}\n]*\b(amount|price|total|cost|quantity|role|isAdmin|admin)\b[^{}\n]*\}\s*=\s*req\.body/;

const RECOMPUTE_KEYWORDS =
  /(calculatePrice|getPrice|computeTotal|priceFor|lookupPrice|server[_-]?side)/i;


// ============================================================
// MAIN SCANNER
// ============================================================

function scanText(filename, text) {
  const findings = [];

  // Static-analysis helpers.
  // These favor recall over perfect precision.
  const add = (
    hit,
    severity,
    ruleId,
    title,
    message,
    snippetIndex = hit.index
  ) => {
    findings.push({
      severity,
      ruleId,
      title,
      message,
      file: filename,
      line: lineOf(text, hit.index),
      snippet: lineText(text, snippetIndex)
    });
  };

  const sourceWindow = (index, radius = 700) =>
    text.slice(
      Math.max(0, index - radius),
      Math.min(text.length, index + radius)
    );


  // ============================================================
  // 1. SECRET EXPOSURE
  // ============================================================

  for (const rule of SECRET_RULES) {
    for (const hit of findAll(rule.re, text)) {
      const snippet = lineText(text, hit.index);

      if (rule.guard && !rule.guard(sourceWindow(hit.index))) {
        continue;
      }

      findings.push({
        severity: rule.severity,
        ruleId: 'secret-exposure',
        title: rule.name + ' exposed in source',
        message:
          `A ${rule.name.toLowerCase()} appears to be hardcoded directly ` +
          `in the file instead of loaded from an environment variable.`,
        file: filename,
        line: lineOf(text, hit.index),
        snippet: redactSecret(snippet)
      });
    }
  }


  // ============================================================
  // 2. CORS
  // ============================================================

  for (const hit of findAll(
    /(?:Access-Control-Allow-Origin['"]?\s*[:=]\s*['"]\*['"]|cors\s*\(\s*\{\s*origin\s*:\s*['"]\*['"]|res\.setHeader\s*\(\s*['"]Access-Control-Allow-Origin['"]\s*,\s*['"]\*['"])/i,
    text
  )) {
    add(
      hit,
      SEVERITY.WARNING,
      'cors-wildcard',
      'CORS allows any origin',
      'The application allows requests from any origin. If authenticated or sensitive endpoints use this policy, review whether arbitrary websites can make browser requests on behalf of users.'
    );
  }


  // ============================================================
  // 3. DYNAMIC CODE EXECUTION
  // ============================================================

  for (const hit of findAll(
    /\beval\s*\(|new\s+Function\s*\(|(?:exec|execSync)\s*\(/,
    text
  )) {
    const window = sourceWindow(hit.index);

    const userInput =
      /(req\.(query|body|params)|request\.(args|form|json|values)|input\s*\(|argv|query_params|searchParams)/i.test(
        window
      );

    add(
      hit,
      userInput ? SEVERITY.CRITICAL : SEVERITY.WARNING,
      'dynamic-code-execution',
      userInput
        ? 'Dynamic code execution may use user input'
        : 'Dynamic code execution',
      userInput
        ? 'A dynamic-code API appears near request/user-controlled input. If that input reaches eval/Function/exec, attacker-controlled code may be executed.'
        : 'eval, Function, exec, or execSync executes dynamically constructed code. Verify that untrusted data cannot reach it.'
    );
  }


  // ============================================================
  // 4. SQL INJECTION — JAVASCRIPT
  // ============================================================

  for (const hit of findAll(
    /\b(?:query|execute|exec|raw|unsafe|run)\s*\(\s*(?:`[^`]*\$\{[^}]+\}[^`]*`|['"][^'"]*['"]\s*\+|[A-Za-z_$][\w$]*\s*\+[^)]*|\w+\s*\.\s*format\s*\()/i,
    text
  )) {
    add(
      hit,
      SEVERITY.CRITICAL,
      'sql-injection',
      'Potential SQL injection',
      'A database query appears to be constructed with interpolation or string concatenation. Use parameterized/bound queries and avoid raw query builders with untrusted input.'
    );
  }


  // ============================================================
  // 5. SQL INJECTION — PYTHON
  // ============================================================

  for (const hit of findAll(
    /\b(?:execute|executemany|executescript|cursor\.execute|connection\.execute)\s*\(\s*(?:f['"`][\s\S]*?\{[^}]+\}[\s\S]*?['"`]|['"`][^'"`]*['"`]\s*\+|['"`][^'"`]*['"`]\s*%\s*(?:\(|[A-Za-z_]))/i,
    text
  )) {
    add(
      hit,
      SEVERITY.CRITICAL,
      'sql-injection-python',
      'Potential SQL injection in Python database call',
      'A Python database call appears to receive an f-string, concatenated string, or %-formatted SQL. Prefer parameterized queries such as execute("... WHERE id = ?", (value,)).'
    );
  }


  // SQL constructed separately and then executed.
  for (const hit of findAll(
    /\b(?:sql|query|statement)\s*=\s*(?:f['"`][\s\S]*?\{[^}]+\}[\s\S]*?['"`]|['"`][\s\S]*?['"`]\s*\+[\s\S]*?)\s*[\r\n;]+[\s\S]{0,300}\b(?:execute|query|raw)\s*\(/i,
    text
  )) {
    add(
      hit,
      SEVERITY.CRITICAL,
      'sql-injection-indirect',
      'Potential SQL injection through constructed SQL variable',
      'SQL is constructed separately and then passed to a database API. Trace the variables used in the SQL expression and replace string construction with parameterized queries.'
    );
  }


  // ============================================================
  // 6. XSS
  // ============================================================

  const requestSource =
    /\b(?:req\.(?:query|body|params)|request\.(?:args|form|json|values)|request\.query_params|searchParams\.get\s*\(|URLSearchParams|location\.(?:search|hash)|input\.value)\b/i;

  const xssSinkPatterns = [
    /res\.(?:send|write|end)\s*\(/i,
    /res\.sendFile\s*\(/i,
    /render_template_string\s*\(/i,
    /render_template\s*\([^)]*,/i,
    /innerHTML\s*=/i,
    /outerHTML\s*=/i,
    /document\.write\s*\(/i,
    /insertAdjacentHTML\s*\(/i,
    /dangerouslySetInnerHTML\s*=/i,
    /\bMarkup\s*\(/i
  ];

  for (const sinkRe of xssSinkPatterns) {
    for (const hit of findAll(sinkRe, text)) {
      const window = sourceWindow(hit.index, 900);

      if (!requestSource.test(window)) {
        continue;
      }

      add(
        hit,
        SEVERITY.CRITICAL,
        'xss',
        'Potential reflected/stored XSS',
        'A browser/HTML output sink appears near request-controlled data. Encode output for its context or use a safe templating/DOM API; do not concatenate untrusted input into HTML.'
      );
    }
  }


  // Flask-specific dynamic template detection.
  for (const hit of findAll(
    /\brender_template_string\s*\(\s*(?:['"`][^)]*['"`]\s*\+|\w+\s*\+|\w+\s*%\s*\w+)/i,
    text
  )) {
    if (
      requestSource.test(sourceWindow(hit.index, 1000)) ||
      /\bname\b|\bquery\b|\binput\b/i.test(sourceWindow(hit.index, 500))
    ) {
      add(
        hit,
        SEVERITY.CRITICAL,
        'xss-template-string',
        'Potential XSS through dynamically constructed template',
        'render_template_string is receiving dynamically constructed HTML. Treat all request-derived values as untrusted and use escaped template variables instead.'
      );
    }
  }


  // ============================================================
  // 7. OS COMMAND INJECTION
  // ============================================================

  const commandSinks = [
    /\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\(/i,
    /\bchild_process\.(?:exec|execSync|spawn|spawnSync)\s*\(/i,
    /\b(?:exec|system|popen)\s*\(/i,
    /\bRuntime\.getRuntime\(\)\.exec\s*\(/i
  ];

  for (const sinkRe of commandSinks) {
    for (const hit of findAll(sinkRe, text)) {
      const window = sourceWindow(hit.index, 900);

      const shellEnabled =
        /\bshell\s*=\s*True\b|\bshell\s*:\s*true\b/i.test(window);

      const dynamicCommand =
        /(?:\+|\$\{|\bf['"`]|format\s*\(|\.format\s*\(|%s|request\.|req\.)/i.test(
          window
        );

      if (dynamicCommand) {
        add(
          hit,
          shellEnabled ? SEVERITY.CRITICAL : SEVERITY.WARNING,
          'command-injection',
          shellEnabled
            ? 'Potential OS command injection'
            : 'Potential command injection',
          shellEnabled
            ? 'A command execution API uses dynamically constructed input with shell execution enabled. Untrusted input can potentially alter the command.'
            : 'A command execution API appears to receive dynamically constructed or request-derived data. Prefer fixed argument arrays and strict allowlists.'
        );
      }
    }
  }


  // ============================================================
  // 8. PATH TRAVERSAL
  // ============================================================

  const fileSinks =
    /\b(?:open|readFile|readFileSync|createReadStream|send_file|sendFile|writeFile|unlink|remove)\s*\(/i;

  for (const hit of findAll(fileSinks, text)) {
    const window = sourceWindow(hit.index, 800);

    if (
      /(?:req\.(?:query|body|params)|request\.(?:args|form|json|values)|searchParams\.get\s*\(|\binput\s*\(|\.\.\/|\.\.\\)/i.test(
        window
      )
    ) {
      add(
        hit,
        SEVERITY.CRITICAL,
        'path-traversal',
        'Potential path traversal / arbitrary file access',
        'A filesystem operation appears to use request-controlled data. Validate against an allowlist and resolve paths under a fixed directory before accessing files.'
      );
    }
  }


  // ============================================================
  // 9. SSRF
  // ============================================================

  for (const hit of findAll(
    /\b(?:fetch|axios\.(?:get|post|request)|requests\.(?:get|post|request)|httpx\.(?:get|post|request)|urllib\.request\.urlopen)\s*\(/i,
    text
  )) {
    const window = sourceWindow(hit.index, 900);

    if (
      /(?:req\.(?:query|body|params)|request\.(?:args|form|json|values)|searchParams\.get\s*\(|user[_-]?input|url\s*=)/i.test(
        window
      )
    ) {
      add(
        hit,
        SEVERITY.WARNING,
        'ssrf',
        'Potential SSRF',
        'A server-side HTTP request appears to use a URL influenced by input. Restrict destinations with an allowlist and block access to internal/cloud metadata addresses.'
      );
    }
  }


  // ============================================================
  // 10. MISSING AUTHENTICATION — NODE
  // ============================================================

  const sensitiveRoute =
    /\b(?:app|router)\.(?:get|post|put|patch|delete)\s*\(\s*['"`](\/[^'"`]*(?:checkout|payment|charge|admin|delete|withdraw|transfer|refund|order|subscribe|account|user|profile)[^'"`]*)['"`]/i;

  for (const hit of findAll(sensitiveRoute, text)) {
    const windowText = text.slice(
      hit.index,
      Math.min(text.length, hit.index + 1600)
    );

    if (!AUTH_KEYWORDS.test(windowText)) {
      add(
        hit,
        SEVERITY.CRITICAL,
        'missing-auth',
        'Sensitive route with no visible auth check',
        'A route with a sensitive name has no recognizable authentication/authorization check in the nearby function body. This is a heuristic and should be manually verified.'
      );
    }
  }


  // ============================================================
  // 11. MISSING AUTHENTICATION — PYTHON
  // ============================================================

  for (const hit of findAll(
    /@(?:app|router)\.(?:route|get|post|put|patch|delete)\s*\(\s*['"]\/[^'"]*(?:admin|payment|delete|transfer|withdraw|account|user|profile)[^'"]*['"]/i,
    text
  )) {
    const windowText = text.slice(
      hit.index,
      Math.min(text.length, hit.index + 1800)
    );

    if (!AUTH_KEYWORDS.test(windowText)) {
      add(
        hit,
        SEVERITY.CRITICAL,
        'missing-auth-python',
        'Sensitive Python route with no visible auth check',
        'A sensitive Flask/FastAPI-style route has no recognizable authentication check nearby. Verify authorization is enforced before accessing or changing protected resources.'
      );
    }
  }


  // ============================================================
  // 12. IDOR / BOLA
  // ============================================================

  const objectIdSource =
    /(?:req\.(?:query|params|body)\.(?:id|userId|accountId|orderId|fileId)|request\.(?:args|form|json|values)\[['"](?:id|user_?id|account_?id|order_?id|file_?id)['"]\]|\b(?:id|user_id|account_id|order_id|file_id)\s*=\s*request\.)/i;

  const objectAccess =
    /\b(?:find(?:One|ById)?|findByPk|findById|findOne|select|SELECT|update|delete|remove|get|fetch|read|open)\b/i;

  for (const hit of findAll(objectAccess, text)) {
    const window = sourceWindow(hit.index, 900);

    if (
      objectIdSource.test(window) &&
      !AUTH_KEYWORDS.test(window)
    ) {
      add(
        hit,
        SEVERITY.CRITICAL,
        'idor-bola',
        'Potential IDOR / broken object-level authorization',
        'An object identifier appears to come from the request and is used to access data without a visible ownership/authorization check. Verify the requester is allowed to access that specific object.'
      );

      break;
    }
  }


  // ============================================================
  // 13. TRUSTING CLIENT INPUT
  // ============================================================

  for (const hit of findAll(CLIENT_TRUST_VARS, text)) {
    const windowText = sourceWindow(hit.index, 900);

    if (!RECOMPUTE_KEYWORDS.test(windowText)) {
      add(
        hit,
        SEVERITY.WARNING,
        'trusting-client-input',
        'Security-sensitive value trusted from the client',
        'A value such as amount, price, quantity, role, or admin status is read directly from request data. Validate authorization and recompute security-sensitive values on the server.'
      );
    }
  }


  // ============================================================
  // 14. MASS ASSIGNMENT
  // ============================================================

  for (const hit of findAll(
    /\b(?:Object\.assign|\.update|\.create|\.insert|\.findOneAndUpdate|\.updateOne)\s*\(\s*(?:[^,]+,\s*)?(?:req\.body|request\.(?:json|form)|body)\b/i,
    text
  )) {
    add(
      hit,
      SEVERITY.WARNING,
      'mass-assignment',
      'Potential mass assignment',
      'A whole request object appears to be passed into a persistence/update operation. Explicitly allowlist fields instead of accepting arbitrary client properties.'
    );
  }


  // ============================================================
  // 15. RATE LIMITING
  // ============================================================

  const hasRateLimit =
    /rate[-_]?limit|express-rate-limit|@upstash\/ratelimit|slowapi|flask[-_]?limiter/i.test(
      text
    );

  const publicEndpoint =
    /(?:webhook|\/login|\/signin|\/signup|\/register|\/forgot[-_]?password|\/reset[-_]?password|\/otp|\/verify)/i;

  if (publicEndpoint.test(text) && !hasRateLimit) {
    const hit = findAll(
      /['"`](?:\/[^'"`]*(?:webhook|login|signin|signup|register|forgot[-_]?password|reset[-_]?password|otp|verify)[^'"`]*)['"`]/i,
      text
    )[0];

    if (hit) {
      add(
        hit,
        SEVERITY.INFO,
        'no-rate-limit',
        'Sensitive public endpoint has no visible rate limiting',
        'A login, registration, password-reset, OTP, verification, or webhook endpoint was found without recognizable rate-limiting middleware in this file. Review brute-force and abuse protections.'
      );
    }
  }


  // ============================================================
  // 16. INSECURE DESERIALIZATION
  // ============================================================

  for (const hit of findAll(
    /\b(?:pickle\.loads?|yaml\.load\s*\(|yaml\.unsafe_load\s*\(|marshal\.loads?|ObjectInputStream|unserialize\s*\()/i,
    text
  )) {
    add(
      hit,
      SEVERITY.CRITICAL,
      'insecure-deserialization',
      'Potential insecure deserialization',
      'A deserialization API that can be unsafe with attacker-controlled data was found. Use safe formats such as JSON where possible and never deserialize untrusted objects.'
    );
  }


  // ============================================================
  // 17. WEAK CRYPTO / TLS
  // ============================================================

  for (const hit of findAll(
    /\b(?:md5|sha1)\s*\(|hashlib\.(?:md5|sha1)\s*\(|(?:ssl|tls|https).*verify\s*[:=]\s*false|rejectUnauthorized\s*:\s*false/i,
    text
  )) {
    add(
      hit,
      SEVERITY.WARNING,
      'weak-crypto-or-tls',
      'Weak cryptography or disabled TLS verification',
      'A weak hash or TLS certificate verification bypass was detected. Do not use MD5/SHA-1 for password/security purposes and do not disable TLS verification in production.'
    );
  }


  // ============================================================
  // 18. DEBUG MODE
  // ============================================================

  for (const hit of findAll(
    /\b(?:app\.run|flask\.run)\s*\([^)]*\bdebug\s*=\s*True\b|\bDEBUG\s*=\s*True\b|\bdebug\s*:\s*true\b/i,
    text
  )) {
    add(
      hit,
      SEVERITY.WARNING,
      'debug-enabled',
      'Debug mode enabled',
      'Development debug mode appears to be enabled. Debug interfaces can expose sensitive information and should not be enabled in production.'
    );
  }


  // ============================================================
  // 19. .ENV FILE
  // ============================================================

  if (/(^|\/)\.env(\..+)?$/.test(filename) && text.trim().length > 0) {
    add(
      { index: 0 },
      SEVERITY.CRITICAL,
      'env-committed',
      '.env file committed to the repo',
      'An environment file is being scanned as repository content. If it contains real secrets and was pushed to a public repository, rotate those credentials.'
    );
  }


  return findings;
}


// ---------- GitHub fetch helpers ----------

const SCANNABLE_EXT = new Set([
  '.js',
  '.jsx',
  '.ts',
  '.tsx',
  '.mjs',
  '.cjs',
  '.py',
  '.env',
  '.example'
]);

const SKIP_PATH =
  /(^|\/)(node_modules|\.git|dist|build|\.next|vendor|coverage)(\/|$)/;

const SKIP_FILE =
  /\.(min\.js|lock|map|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|pdf)$/i;

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

  if (!/(^|\.)github\.com$/.test(url.hostname)) {
    return null;
  }

  const parts = url.pathname.split('/').filter(Boolean);

  if (parts.length < 2) {
    return null;
  }

  const owner = parts[0];
  const repo = parts[1].replace(/\.git$/, '');

  let branch = null;

  if (parts[2] === 'tree' && parts[3]) {
    branch = decodeURIComponent(parts[3]);
  }

  return {
    owner,
    repo,
    branch
  };
}
 async function githubJson(url) {
  const r = await fetch(url, {
    headers: {
      Accept: 'application/vnd.github+json',
      'User-Agent': 'redline-scanner-prototype'
    }
  });

  if (r.status === 403) {
    let body = {};

    try {
      body = await r.json();
    } catch (e) {}

    const err = new Error(
      body.message || 'GitHub API rate limit reached'
    );

    err.code = 'RATE_LIMIT';

    throw err;
  }

  if (r.status === 404) {
    const err = new Error(
      'Repository not found or private'
    );

    err.code = 'NOT_FOUND';

    throw err;
  }

  if (!r.ok) {
    const err = new Error(
      'GitHub API error (' + r.status + ')'
    );

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

    const ext = entry.path.includes('.')
      ? entry.path.slice(entry.path.lastIndexOf('.'))
      : '';

    const base = entry.path.split('/').pop();

    if (base.startsWith('.env')) return true;

    if (!SCANNABLE_EXT.has(ext)) return false;

    if (entry.size && entry.size > MAX_SINGLE_FILE_BYTES) {
      return false;
    }

    return true;
  });

  const priorityHint =
    /(route|checkout|payment|webhook|api|admin|auth|server|\.env)/i;

  candidates.sort((a, b) => {
    const pa = priorityHint.test(a.path) ? 0 : 1;
    const pb = priorityHint.test(b.path) ? 0 : 1;

    if (pa !== pb) return pa - pb;

    return (a.size || 0) - (b.size || 0);
  });

  const selected = [];

  let totalBytes = 0;

  for (const entry of candidates) {
    if (selected.length >= MAX_FILES) {
      break;
    }

    const size = entry.size || 0;

    if (totalBytes + size > MAX_TOTAL_BYTES) {
      continue;
    }

    selected.push(entry);
    totalBytes += size;
  }

  return selected;
}


async function fetchRaw(owner, repo, branch, path) {
  const encodedPath = path
    .split('/')
    .map(encodeURIComponent)
    .join('/');

  const url =
    'https://raw.githubusercontent.com/' +
    owner +
    '/' +
    repo +
    '/' +
    encodeURIComponent(branch) +
    '/' +
    encodedPath;

  const r = await fetch(url);

  if (!r.ok) {
    return null;
  }

  return r.text();
}


function summarize(findings) {
  const summary = {
    critical: 0,
    warning: 0,
    info: 0
  };

  for (const f of findings) {
    summary[f.severity]++;
  }

  return summary;
}


const severityRank = {
  critical: 0,
  warning: 1,
  info: 2
};
// ---------- handler ----------

module.exports = async function handler(req, res) {
  try {
    res.setHeader(
      'Access-Control-Allow-Origin',
      '*'
    );

    res.setHeader(
      'Access-Control-Allow-Methods',
      'POST, OPTIONS'
    );

    res.setHeader(
      'Access-Control-Allow-Headers',
      'Content-Type'
    );

    if (req.method === 'OPTIONS') {
      res.status(204).end();
      return;
    }

    if (req.method !== 'POST') {
      res.status(405).json({
        error: 'Use POST'
      });

      return;
    }


    let body = req.body;

    if (typeof body === 'string') {
      try {
        body = JSON.parse(body);
      } catch (e) {
        body = {};
      }
    }

    if (!body || typeof body !== 'object') {
      body = {};
    }


    const mode = body.mode;
    const value = body.value;


    if (
      !value ||
      typeof value !== 'string' ||
      !value.trim()
    ) {
      res.status(400).json({
        error:
          'Nothing to scan — paste some code or a GitHub repo URL.'
      });

      return;
    }


    // ==========================================================
    // CODE MODE
    // ==========================================================

    if (mode === 'code') {
      const text = value.slice(
        0,
        MAX_SINGLE_FILE_BYTES
      );

      const findings = scanText(
        'pasted-code',
        text
      );

      findings.sort(
        (a, b) =>
          severityRank[a.severity] -
          severityRank[b.severity]
      );

      res.status(200).json({
        target: 'Pasted code',
        filesScanned: 1,
        findings,
        summary: summarize(findings)
      });

      return;
    }


    // ==========================================================
    // REPOSITORY MODE
    // ==========================================================

    if (mode === 'repo') {
      const parsed = parseGithubUrl(value);

      if (!parsed) {
        res.status(400).json({
          error:
            'That doesn\'t look like a GitHub repo URL, e.g. https://github.com/owner/repo'
        });

        return;
      }


      const owner = parsed.owner;
      const repo = parsed.repo;

      let branch = parsed.branch;


      try {
        // Get default branch if one wasn't explicitly provided.
        if (!branch) {
          const repoMeta = await githubJson(
            'https://api.github.com/repos/' +
              owner +
              '/' +
              repo
          );

          branch = repoMeta.default_branch;
        }


        // Get complete repository tree.
        const treeData = await githubJson(
          'https://api.github.com/repos/' +
            owner +
            '/' +
            repo +
            '/git/trees/' +
            encodeURIComponent(branch) +
            '?recursive=1'
        );


        const files = pickFiles(
          treeData.tree || []
        );


        if (files.length === 0) {
          res.status(200).json({
            target: owner + '/' + repo,
            filesScanned: 0,
            findings: [],
            summary: {
              critical: 0,
              warning: 0,
              info: 0
            },
            note:
              'No JS/TS/Python files matched — nothing scanned.'
          });

          return;
        }


        const contents = await Promise.all(
          files.map((f) =>
            fetchRaw(
              owner,
              repo,
              branch,
              f.path
            ).catch(() => null)
          )
        );


        let findings = [];
        let scanned = 0;


        contents.forEach((text, i) => {
          if (text == null) {
            return;
          }

          scanned++;

          findings = findings.concat(
            scanText(
              files[i].path,
              text
            )
          );
        });


        findings.sort(
          (a, b) =>
            severityRank[a.severity] -
            severityRank[b.severity]
        );


        res.status(200).json({
          target: owner + '/' + repo,
          branch,
          filesScanned: scanned,
          findings,
          summary: summarize(findings)
        });

        return;
              } catch (err) {
        if (err.code === 'RATE_LIMIT') {
          res.status(429).json({
            error:
              'GitHub\'s free API rate limit was hit for this server. Try again in a few minutes, or paste code directly instead.'
          });

          return;
        }


        if (err.code === 'NOT_FOUND') {
          res.status(404).json({
            error:
              'Repo not found — check the URL, and note only public repos can be scanned in this prototype.'
          });

          return;
        }


        res.status(500).json({
          error:
            'Scan failed: ' +
            (
              err && err.message
                ? err.message
                : String(err)
            )
        });

        return;
      }
    }


    res.status(400).json({
      error:
        'mode must be "code" or "repo"'
    });


  } catch (outerErr) {
    // Last-resort guard: whatever happens, always return valid JSON.
    try {
      res.status(500).json({
        error:
          'Unexpected server error: ' +
          (
            outerErr && outerErr.message
              ? outerErr.message
              : String(outerErr)
          )
      });
    } catch (e) {
      res.end(
        '{"error":"Unexpected server error"}'
      );
    }
  }
};

