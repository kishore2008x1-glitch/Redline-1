// api/explain.js
// On-demand AI fix suggestions for a single finding, via Gemini's free-tier API.
// SECURITY: the API key is read from process.env.GEMINI_API_KEY (a Vercel
// environment variable) — it is never present in this file, never sent to
// the browser, and never logged. Set it with:
//   vercel env add GEMINI_API_KEY
// or via the Vercel dashboard → Project → Settings → Environment Variables.
// If it isn't set, this endpoint returns a clear error instead of crashing,
// and the rest of the scanner keeps working with zero AI involvement.

const GEMINI_MODEL = process.env.GEMINI_MODEL || 'gemini-3.6-flash';
const GEMINI_URL = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent`;

const MAX_SNIPPET_CHARS = 2000; // keep prompts small — this is a free-tier key
const MAX_REQUESTS_PER_MIN = 20; // crude in-memory throttle, resets on cold start

let windowStart = Date.now();
let windowCount = 0;
function rateLimited() {
  const now = Date.now();
  if (now - windowStart > 60000) { windowStart = now; windowCount = 0; }
  windowCount++;
  return windowCount > MAX_REQUESTS_PER_MIN;
}

module.exports = async function handler(req, res) {
  try {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') { res.status(204).end(); return; }
    if (req.method !== 'POST') { res.status(405).json({ error: 'Use POST' }); return; }

    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      res.status(501).json({
        error: 'AI fix suggestions aren\'t configured on this deployment yet. Set GEMINI_API_KEY as a Vercel environment variable (never in client code) and redeploy.',
      });
      return;
    }

    if (rateLimited()) {
      res.status(429).json({ error: 'AI suggestions are rate-limited to protect the free-tier quota. Try again in a minute.' });
      return;
    }

    let body = req.body;
    if (typeof body === 'string') {
      try { body = JSON.parse(body); } catch (e) { body = {}; }
    }
    if (!body || typeof body !== 'object') body = {};

    const { title, message, snippet, file, ruleId } = body;
    if (!title || typeof title !== 'string') {
      res.status(400).json({ error: 'Missing finding details to explain.' });
      return;
    }

    const safeSnippet = typeof snippet === 'string' ? snippet.slice(0, MAX_SNIPPET_CHARS) : '';
    const prompt =
      `You are a terse security code reviewer. A static scanner found this issue:\n\n` +
      `Rule: ${ruleId || 'unknown'}\n` +
      `Title: ${title}\n` +
      `File: ${file || 'unknown'}\n` +
      `Scanner note: ${message || ''}\n` +
      `Code snippet:\n${safeSnippet}\n\n` +
      `In under 120 words: 1) confirm briefly whether this looks like a real issue or a likely false positive given only this snippet, and 2) show a minimal corrected version of the snippet. ` +
      `Do not add unrelated advice. Use plain text, not markdown headers.`;

    const geminiRes = await fetch(GEMINI_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-goog-api-key': apiKey,
      },
      body: JSON.stringify({
        contents: [{ role: 'user', parts: [{ text: prompt }] }],
        generationConfig: { maxOutputTokens: 300, temperature: 0.2 },
      }),
    });

    if (geminiRes.status === 429) {
      res.status(429).json({ error: 'Gemini\'s free-tier quota was hit for this key. Try again shortly.' });
      return;
    }
    if (geminiRes.status === 400 || geminiRes.status === 403) {
      const errBody = await geminiRes.json().catch(() => ({}));
      res.status(502).json({ error: 'Gemini rejected the request — check that GEMINI_API_KEY is valid: ' + (errBody.error && errBody.error.message ? errBody.error.message : geminiRes.status) });
      return;
    }
    if (!geminiRes.ok) {
      const errBody = await geminiRes.text().catch(() => '');
      res.status(502).json({ error: 'Gemini API error (' + geminiRes.status + '): ' + errBody.slice(0, 300) });
      return;
    }

    const data = await geminiRes.json();
    const text = data && data.candidates && data.candidates[0] && data.candidates[0].content &&
      data.candidates[0].content.parts && data.candidates[0].content.parts[0] &&
      data.candidates[0].content.parts[0].text;

    if (!text) {
      res.status(502).json({ error: 'Gemini returned no suggestion for this finding.' });
      return;
    }

    res.status(200).json({ suggestion: text.trim() });
  } catch (outerErr) {
    try {
      res.status(500).json({ error: 'Unexpected server error: ' + (outerErr && outerErr.message ? outerErr.message : String(outerErr)) });
    } catch (e) {
      res.end('{"error":"Unexpected server error"}');
    }
  }
};
