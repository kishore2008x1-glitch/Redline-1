// api/explain.js
// Redline — AI security finding explanation / fix suggestion endpoint.
//
// SECURITY:
// - GEMINI_API_KEY is server-side only.
// - Never put the Gemini key in index.html or client-side JavaScript.
// - Configure the key in Vercel Environment Variables and redeploy.
//
// Required Vercel variable:
//   GEMINI_API_KEY=your_key
//
// Optional:
//   GEMINI_MODEL=gemini-3.7-flash
//
// The endpoint uses Google's Gemini REST generateContent API.
// It retries temporary 503/429 responses and can fall back to
// other currently supported text models.

const PRIMARY_MODEL = process.env.GEMINI_MODEL || 'gemini-3.7-flash';

// Fallbacks are deliberately stable/current models.
// If you set GEMINI_MODEL, it becomes the first model attempted.
const FALLBACK_MODELS = [
  PRIMARY_MODEL,
  'gemini-3.6-flash',
  'gemini-2.5-flash'
].filter((model, index, arr) => model && arr.indexOf(model) === index);

const MAX_SNIPPET_CHARS = 2000;
const MAX_TEXT_CHARS = 4000;
const MAX_REQUESTS_PER_MIN = 20;
const REQUEST_TIMEOUT_MS = 25000;
const MAX_RETRIES_PER_MODEL = 2;

let windowStart = Date.now();
let windowCount = 0;

function rateLimited() {
  const now = Date.now();

  if (now - windowStart >= 60000) {
    windowStart = now;
    windowCount = 0;
  }

  windowCount += 1;
  return windowCount > MAX_REQUESTS_PER_MIN;
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function cleanText(value, maxLength) {
  if (typeof value !== 'string') return '';
  return value.replace(/\u0000/g, '').slice(0, maxLength).trim();
}

function modelUrl(model) {
  return (
    `https://generativelanguage.googleapis.com/v1beta/models/` +
    `${encodeURIComponent(model)}:generateContent`
  );
}

async function fetchWithTimeout(url, options, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(url, {
      ...options,
      signal: controller.signal
    });
  } finally {
    clearTimeout(timer);
  }
}

async function parseGeminiError(response) {
  let payload = null;

  try {
    payload = await response.json();
  } catch (_) {
    // Response wasn't JSON.
  }

  const message =
    payload?.error?.message ||
    payload?.error?.status ||
    '';

  return {
    status: response.status,
    message: message || `HTTP ${response.status}`,
    payload
  };
}

function buildPrompt({ title, message, snippet, file, ruleId }) {
  return [
    'You are Redline, an application-security code reviewer.',
    'Analyze only the supplied security finding and code context.',
    '',
    `Rule: ${ruleId || 'unknown'}`,
    `Title: ${title || 'unknown'}`,
    `File: ${file || 'unknown'}`,
    `Scanner note: ${message || 'none'}`,
    '',
    'Code snippet:',
    snippet || '(no code snippet supplied)',
    '',
    'Return a concise response with exactly these sections:',
    'Assessment: Say whether this appears to be a real issue, likely false positive, or cannot be determined from the supplied context.',
    'Why it matters: Explain the security impact in simple terms.',
    'Fix: Give the smallest practical corrected code when enough context exists. If there is not enough context, explain what additional context is needed instead of inventing code.',
    'Verification: Give one short way to verify the fix.',
    '',
    'Keep the response under 220 words.',
    'Do not claim that code is vulnerable unless the supplied evidence supports that conclusion.',
    'Do not invent files, functions, dependencies, APIs, or application behavior.'
  ].join('\n');
}

async function callModel(model, apiKey, prompt) {
  const url = modelUrl(model);

  const requestBody = {
    contents: [
      {
        parts: [
          {
            text: prompt
          }
        ]
      }
    ],
    generationConfig: {
      temperature: 0.2,
      maxOutputTokens: 700
    }
  };

  let lastResult = null;

  for (let attempt = 0; attempt <= MAX_RETRIES_PER_MODEL; attempt += 1) {
    try {
      const response = await fetchWithTimeout(
        url,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-goog-api-key': apiKey
          },
          body: JSON.stringify(requestBody)
        },
        REQUEST_TIMEOUT_MS
      );

      if (response.ok) {
        return {
          ok: true,
          response,
          model
        };
      }

      const error = await parseGeminiError(response);
      lastResult = {
        ok: false,
        ...error,
        model
      };

      // Retry only temporary capacity/rate-limit errors.
      if (response.status !== 503 && response.status !== 429) {
        return lastResult;
      }

      if (attempt < MAX_RETRIES_PER_MODEL) {
        // Exponential backoff with small jitter.
        const delay =
          Math.min(1000 * (2 ** attempt), 6000) +
          Math.floor(Math.random() * 300);

        await sleep(delay);
      }
    } catch (error) {
      const message =
        error?.name === 'AbortError'
          ? 'Gemini request timed out.'
          : (error?.message || 'Network error contacting Gemini.');

      lastResult = {
        ok: false,
        status: 0,
        message,
        model,
        networkError: true
      };

      // Retry transient network/time-out failures.
      if (attempt < MAX_RETRIES_PER_MODEL) {
        const delay =
          Math.min(1000 * (2 ** attempt), 6000) +
          Math.floor(Math.random() * 300);

        await sleep(delay);
      }
    }
  }

  return lastResult;
}

function extractText(data) {
  const candidates = Array.isArray(data?.candidates)
    ? data.candidates
    : [];

  const text = candidates
    .flatMap(candidate =>
      Array.isArray(candidate?.content?.parts)
        ? candidate.content.parts
        : []
    )
    .map(part => typeof part?.text === 'string' ? part.text : '')
    .join('')
    .trim();

  return {
    text,
    candidate: candidates[0] || null
  };
}

module.exports = async function handler(req, res) {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }

  if (req.method !== 'POST') {
    res.status(405).json({
      error: 'Method not allowed. Use POST /api/explain.'
    });
    return;
  }

  try {
    const apiKey = process.env.GEMINI_API_KEY;

    if (!apiKey || typeof apiKey !== 'string' || !apiKey.trim()) {
      res.status(503).json({
        error:
          'Gemini AI is not configured. Add GEMINI_API_KEY to ' +
          'Vercel Environment Variables and redeploy.'
      });
      return;
    }

    if (rateLimited()) {
      res.status(429).json({
        error:
          'Redline AI is temporarily rate-limited. Please try again shortly.'
      });
      return;
    }

    let body = req.body;

    if (typeof body === 'string') {
      try {
        body = JSON.parse(body);
      } catch (_) {
        body = null;
      }
    }

    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      res.status(400).json({
        error: 'Invalid JSON request body.'
      });
      return;
    }

    const title = cleanText(body.title, 500);
    const message = cleanText(body.message, 1500);
    const snippet = cleanText(body.snippet, MAX_SNIPPET_CHARS);
    const file = cleanText(body.file, 500);
    const ruleId = cleanText(body.ruleId, 200);

    if (!title) {
      res.status(400).json({
        error: 'Missing finding title.'
      });
      return;
    }

    const prompt = buildPrompt({
      title,
      message,
      snippet,
      file,
      ruleId
    });

    let successfulResponse = null;
    let lastError = null;

    // Try the primary model, then fall back only when appropriate.
    for (const model of FALLBACK_MODELS) {
      const result = await callModel(model, apiKey.trim(), prompt);

      if (result.ok) {
        successfulResponse = result;
        break;
      }

      lastError = result;

      // Invalid request/auth/model errors won't be fixed by retrying
      // every other model, except a model-not-found error.
      if (
        result.status === 401 ||
        result.status === 403 ||
        (result.status === 400 &&
          !/model|not found|unsupported/i.test(result.message || ''))
      ) {
        break;
      }

      // Continue to the next model for capacity, quota, or model availability.
      if (
        result.status === 429 ||
        result.status === 503 ||
        result.status === 404
      ) {
        continue;
      }

      // Network errors can also try the next model.
      if (result.networkError) {
        continue;
      }

      break;
    }

    if (!successfulResponse) {
      const status = lastError?.status || 502;
      const detail = lastError?.message || 'Unknown Gemini error.';
      const model = lastError?.model || PRIMARY_MODEL;

      if (status === 401) {
        res.status(502).json({
          error:
            'Gemini authentication failed. Check that GEMINI_API_KEY ' +
            'is valid, active, and belongs to the intended Google project.'
        });
        return;
      }

      if (status === 403) {
        res.status(502).json({
          error:
            'Gemini denied the request. Check API-key restrictions, ' +
            'project permissions, billing/quota configuration, and model access.'
        });
        return;
      }

      if (status === 429) {
        res.status(429).json({
          error:
            'Gemini rate limit or quota was reached. Please try again shortly.'
        });
        return;
      }

      if (status === 400) {
        res.status(502).json({
          error:
            `Gemini rejected the request (400 INVALID_ARGUMENT): ${detail}`
        });
        return;
      }

      if (status === 404) {
        res.status(502).json({
          error:
            `Gemini model "${model}" was not found or is not available ` +
            `for this API project. Check GEMINI_MODEL.`
        });
        return;
      }

      if (status === 503) {
        res.status(503).json({
          error:
            'Gemini is temporarily unavailable because the selected models ' +
            'are experiencing capacity pressure. Redline retried the request ' +
            'and tried its configured fallbacks. Please try again shortly.'
        });
        return;
      }

      if (lastError?.networkError) {
        res.status(502).json({
          error:
            'Redline could not reach Gemini from the server. ' +
            'Check the Vercel function logs and outbound network configuration.'
        });
        return;
      }

      res.status(502).json({
        error:
          `Gemini API error (${status}): ${detail}`
      });
      return;
    }

    const data = await successfulResponse.response.json();
    const { text, candidate } = extractText(data);

    if (!text) {
      const finishReason = candidate?.finishReason;

      res.status(502).json({
        error:
          'Gemini returned no text suggestion' +
          (finishReason
            ? ` (finishReason: ${finishReason})`
            : '') +
          '.'
      });
      return;
    }

    const truncated =
      candidate?.finishReason === 'MAX_TOKENS';

    res.status(200).json({
      suggestion:
        text +
        (truncated
          ? '\n\n[Response shortened because it reached the token limit.]'
          : ''),
      model: successfulResponse.model
    });

  } catch (error) {
    console.error(
      'Redline /api/explain error:',
      error?.message || error
    );

    res.status(500).json({
      error:
        'Unexpected server error while generating the AI suggestion.'
    });
  }
};
