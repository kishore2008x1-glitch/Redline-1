// api/scan.js
// Vercel Serverless Function (Node runtime). No API keys required:
// - GitHub's REST API allows unauthenticated read access to public repos (60 req/hr per IP).
// - Everything else is local pattern matching in lib/rules.js.

const { scanText, SEVERITY } = require('../lib/rules');

const SCANNABLE_EXT = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py', '.env', '.example',
]);
const SKIP_PATH = /(^|\/)(node_modules|\.git|dist|build|\.next|vendor|coverage)(\/|$)/;
const SKIP_FILE = /\.(min\.js|lock|map|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|pdf)$/i;

const MAX_FILES = 25;
const MAX_TOTAL_BYTES = 450_000; // keep well under function time/memory limits
const MAX_SINGLE_FILE_BYTES = 120_000;

function jsonResponse(res, status, body) {
  res.status(status).json(body);
}

function parseGithubUrl(raw) {
  let url;
  try {
    url = new URL(raw.trim());
  } catch {
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
    const body = await r.json().catch(() => ({}));
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
    const err = new Error(`GitHub API error (${r.status})`);
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

  // Prioritize files most likely to hold the interesting findings.
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
  const url = `https://raw.githubusercontent.com/${owner}/${repo}/${encodeURIComponent(branch)}/${encodedPath}`;
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

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return jsonResponse(res, 405, { error: 'Use POST' });

  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch { body = {}; }
  }
  const { mode, value } = body || {};

  if (!value || typeof value !== 'string' || !value.trim()) {
    return jsonResponse(res, 400, { error: 'Nothing to scan — paste some code or a GitHub repo URL.' });
  }

  try {
    if (mode === 'code') {
      const text = value.slice(0, MAX_SINGLE_FILE_BYTES);
      const findings = scanText('pasted-code', text);
      findings.sort((a, b) => severityRank[a.severity] - severityRank[b.severity]);
      return jsonResponse(res, 200, {
        target: 'Pasted code',
        filesScanned: 1,
        findings,
        summary: summarize(findings),
      });
    }

    if (mode === 'repo') {
      const parsed = parseGithubUrl(value);
      if (!parsed) {
        return jsonResponse(res, 400, { error: 'That doesn\'t look like a GitHub repo URL, e.g. https://github.com/owner/repo' });
      }
      const { owner, repo } = parsed;
      let branch = parsed.branch;
      if (!branch) {
        const repoMeta = await githubJson(`https://api.github.com/repos/${owner}/${repo}`);
        branch = repoMeta.default_branch;
      }
      const treeData = await githubJson(
        `https://api.github.com/repos/${owner}/${repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`
      );
      if (treeData.truncated) {
        // still proceed with what we got — prototype, not a full crawler
      }
      const files = pickFiles(treeData.tree || []);
      if (files.length === 0) {
        return jsonResponse(res, 200, {
          target: `${owner}/${repo}`,
          filesScanned: 0,
          findings: [],
          summary: { critical: 0, warning: 0, info: 0 },
          note: 'No JS/TS/Python files matched — nothing scanned.',
        });
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

      return jsonResponse(res, 200, {
        target: `${owner}/${repo}`,
        branch,
        filesScanned: scanned,
        findings,
        summary: summarize(findings),
      });
    }

    return jsonResponse(res, 400, { error: 'mode must be "code" or "repo"' });
  } catch (err) {
    if (err.code === 'RATE_LIMIT') {
      return jsonResponse(res, 429, { error: 'GitHub\'s free API rate limit was hit for this server. Try again in a few minutes, or paste code directly instead.' });
    }
    if (err.code === 'NOT_FOUND') {
      return jsonResponse(res, 404, { error: 'Repo not found — check the URL, and note only public repos can be scanned in this prototype.' });
    }
    return jsonResponse(res, 500, { error: 'Scan failed: ' + err.message });
  }
};
