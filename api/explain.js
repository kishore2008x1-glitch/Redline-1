// api/explain.js
// On-demand AI fix suggestions for a single finding, via Gemini API.
//
// SECURITY:
// - GEMINI_API_KEY is read only from process.env.
// - The key is never sent to the browser.
// - The key is never logged.
// - Set GEMINI_API_KEY in Vercel Environment Variables.
//
// Optional:
// GEMINI_MODEL=gemini-3.7-flash

const GEMINI_MODELS = [
  process.env.GEMINI_MODEL || 'gemini-3.7-flash',
  'gemini-3.6-flash',
  'gemini-3.5-flash'
];
const GEMINI_URL =
  `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent`;

const MAX_SNIPPET_CHARS = 2000;
const MAX_REQUESTS_PER_MIN = 20;


// -----------------------------------------------------------------------------
// Simple in-memory rate limiter
// -----------------------------------------------------------------------------

let windowStart = Date.now();
let windowCount = 0;

function rateLimited() {
  const now = Date.now();

  if (now - windowStart > 60000) {
    windowStart = now;
    windowCount = 0;
  }

  windowCount++;

  return windowCount > MAX_REQUESTS_PER_MIN;
}


// -----------------------------------------------------------------------------
// Safe error extraction
// -----------------------------------------------------------------------------

async function readGeminiError(response) {
  try {
    const body = await response.json();

    return (
      body?.error?.message ||
      body?.error?.status ||
      JSON.stringify(body)
    );
  } catch (e) {
    try {
      return await response.text();
    } catch (err) {
      return `HTTP ${response.status}`;
    }
  }
}


// -----------------------------------------------------------------------------
// API handler
// -----------------------------------------------------------------------------
async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function callGemini(url, options, maxRetries = 3) {
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    const response = await fetch(url, options);

    if (response.status !== 503 && response.status !== 429) {
      return response;
    }

    if (attempt === maxRetries) {
      return response;
    }

    const delay = Math.min(
      1000 * Math.pow(2, attempt),
      8000
    );

    const jitter = Math.random() * 500;

    await sleep(delay + jitter);
  }
}
module.exports = async function handler(req, res) {
  try {
    // CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader(
      'Access-Control-Allow-Methods',
      'POST, OPTIONS'
    );
    res.setHeader(
      'Access-Control-Allow-Headers',
      'Content-Type'
    );

    // Preflight
    if (req.method === 'OPTIONS') {
      res.status(204).end();
      return;
    }

    // Only POST
    if (req.method !== 'POST') {
      res.status(405).json({
        error: 'Use POST'
      });
      return;
    }


    // -------------------------------------------------------------------------
    // Gemini API key
    // -------------------------------------------------------------------------

    const apiKey = process.env.GEMINI_API_KEY;

    if (!apiKey) {
      res.status(501).json({
        error:
          'Gemini AI is not configured on this deployment. ' +
          'Set GEMINI_API_KEY in your Vercel Environment Variables ' +
          'and redeploy.'
      });

      return;
    }


    // -------------------------------------------------------------------------
    // Rate limiting
    // -------------------------------------------------------------------------

    if (rateLimited()) {
      res.status(429).json({
        error:
          'AI suggestions are temporarily rate-limited. ' +
          'Please try again in a minute.'
      });

      return;
    }


    // -------------------------------------------------------------------------
    // Parse request body
    // -------------------------------------------------------------------------

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


    // -------------------------------------------------------------------------
    // Extract finding information
    // -------------------------------------------------------------------------

    const {
      title,
      message,
      snippet,
      file,
      ruleId
    } = body;

    if (!title || typeof title !== 'string') {
      res.status(400).json({
        error: 'Missing finding details to explain.'
      });

      return;
    }


    // -------------------------------------------------------------------------
    // Limit snippet size
    // -------------------------------------------------------------------------

    const safeSnippet =
      typeof snippet === 'string'
        ? snippet.slice(0, MAX_SNIPPET_CHARS)
        : '';


    // -------------------------------------------------------------------------
    // Security-review prompt
    // -------------------------------------------------------------------------

    const prompt =
      `You are a concise application security code reviewer.

A static security scanner found the following issue:

Rule: ${ruleId || 'unknown'}

Title: ${title}

File: ${file || 'unknown'}

Scanner note:
${message || ''}

Code snippet:
${safeSnippet}

Your task:

1. Briefly determine whether this appears to be a real security issue or a likely false positive based only on the supplied snippet.
2. Explain the security problem in simple terms.
3. Provide a minimal corrected version of the relevant code when possible.
4. Do not invent surrounding application code.
5. Do not provide unrelated recommendations.

Keep the response under 180 words.
Use plain text with short sections.
Do not use markdown headers.`;


    // -------------------------------------------------------------------------
    // Gemini request
    //
    // Uses Google's REST generateContent endpoint.
    // The current Gemini documentation supports this request structure.
    // -------------------------------------------------------------------------

     let geminiRes;
let lastError = '';

for (const model of GEMINI_MODELS) {
  const url =
    `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;

  geminiRes = await callGemini(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-goog-api-key': apiKey
    },
    body: JSON.stringify({
      contents: [
        {
          role: 'user',
          parts: [{ text: prompt }]
        }
      ],
      generationConfig: {
        maxOutputTokens: 600,
        temperature: 0.2
      }
    })
  });

  if (geminiRes.ok) {
    break;
  }

  lastError = await readGeminiError(geminiRes);

  // Only fall back for temporary capacity problems.
  if (geminiRes.status !== 503) {
    break;
  }
}


    // -------------------------------------------------------------------------
    // Handle Gemini errors
    // -------------------------------------------------------------------------

    if (!geminiRes.ok) {
      const geminiError =
        await readGeminiError(geminiRes);

      // Rate limit / quota
      if (geminiRes.status === 429) {
        res.status(429).json({
          error:
            'Gemini rate limit or quota reached. ' +
            geminiError
        });

        return;
      }


      // Authentication / permission
      if (geminiRes.status === 401) {
        res.status(502).json({
          error:
            'Gemini authentication failed. ' +
            'Check that GEMINI_API_KEY is correct and active.'
        });

        return;
      }


      // Invalid request
      if (geminiRes.status === 400) {
        res.status(502).json({
          error:
            'Gemini rejected the request (400 INVALID_ARGUMENT): ' +
            geminiError,
          model: GEMINI_MODEL
        });

        return;
      }


      // Forbidden
      if (geminiRes.status === 403) {
        res.status(502).json({
          error:
            'Gemini denied this request (403). ' +
            geminiError
        });

        return;
      }


      // Model not found
      if (geminiRes.status === 404) {
        res.status(502).json({
          error:
            `Gemini model "${GEMINI_MODEL}" was not found. ` +
            'Check GEMINI_MODEL and your enabled API models.'
        });

        return;
      }


      // Other Gemini errors
      res.status(502).json({
        error:
          `Gemini API error (${geminiRes.status}): ` +
          geminiError
      });

      return;
    }


    // -------------------------------------------------------------------------
    // Parse successful response
    // -------------------------------------------------------------------------

    const data = await geminiRes.json();

    const candidate =
      data &&
      data.candidates &&
      data.candidates[0];

    const parts =
      candidate &&
      candidate.content &&
      candidate.content.parts;


    // Gemini may return multiple parts.
    const text =
      Array.isArray(parts)
        ? parts
            .map(part => part?.text || '')
            .join('')
            .trim()
        : '';


    // -------------------------------------------------------------------------
    // No response text
    // -------------------------------------------------------------------------

    if (!text) {
      const finishReason =
        candidate?.finishReason;

      res.status(502).json({
        error:
          'Gemini returned no text suggestion' +
          (
            finishReason
              ? ` (finishReason: ${finishReason})`
              : ''
          ) +
          '.'
      });

      return;
    }


    // -------------------------------------------------------------------------
    // Return suggestion
    // -------------------------------------------------------------------------

    res.status(200).json({
      suggestion: text
    });


  } catch (outerErr) {

    console.error(
      'Redline Gemini endpoint error:',
      outerErr?.message || outerErr
    );

    try {
      res.status(500).json({
        error:
          'Unexpected server error: ' +
          (
            outerErr?.message ||
            String(outerErr)
          )
      });
    } catch (e) {
      res.end(
        '{"error":"Unexpected server error"}'
      );
    }
  }
};
