/**
 * Hardened version of the tealkin-proxy Cloudflare Worker.
 * Merged from the real Worker code (DeepSeek /v1/chat/completions proxy,
 * secret bound as `DeepSeek`) plus abuse protections:
 *   1. Origin allow-list — only tealkin.com can call this.
 *   2. Payload size cap — rejects oversized bodies before forwarding.
 *   3. Per-IP rate limiting via the RATE_LIMIT_KV binding already added.
 *
 * Paste this into the Worker's "Edit code" view, replacing the existing
 * content, then Save and Deploy.
 */

const ALLOWED_ORIGINS = new Set([
  'https://tealkin.com',
  'https://www.tealkin.com',
]);

const MAX_BODY_BYTES = 20_000;          // reject payloads bigger than this
const RATE_LIMIT_MAX = 20;               // max requests
const RATE_LIMIT_WINDOW_SECONDS = 600;   // ...per 10 minutes, per IP

function corsHeaders(origin) {
  const allowOrigin = ALLOWED_ORIGINS.has(origin) ? origin : 'https://tealkin.com';
  return {
    'Access-Control-Allow-Origin': allowOrigin,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Vary': 'Origin',
  };
}

async function checkRateLimit(env, ip) {
  const key = `rl:${ip}`;
  const current = await env.RATE_LIMIT_KV.get(key);
  const count = current ? parseInt(current, 10) : 0;

  if (count >= RATE_LIMIT_MAX) return false;

  await env.RATE_LIMIT_KV.put(key, String(count + 1), {
    expirationTtl: RATE_LIMIT_WINDOW_SECONDS,
  });
  return true;
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const headers = corsHeaders(origin);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers });
    }

    if (request.method !== 'POST') {
      return new Response('Method not allowed', { status: 405, headers });
    }

    // 1. Origin allow-list — block calls that don't come from the site itself
    if (!ALLOWED_ORIGINS.has(origin)) {
      return new Response('Forbidden', { status: 403, headers });
    }

    // 2. Payload size cap, checked on the actual body (no Content-Length trust)
    const body = await request.text();
    if (body.length > MAX_BODY_BYTES) {
      return new Response('Payload too large', { status: 413, headers });
    }

    // 3. Per-IP rate limit
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const allowed = await checkRateLimit(env, ip);
    if (!allowed) {
      return new Response('Too many requests, slow down.', { status: 429, headers });
    }

    const response = await fetch('https://api.deepseek.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${env.DeepSeek}`,
      },
      body: body,
    });

    const data = await response.text();

    return new Response(data, {
      status: response.status,
      headers: { ...headers, 'Content-Type': 'application/json' },
    });
  },
};
