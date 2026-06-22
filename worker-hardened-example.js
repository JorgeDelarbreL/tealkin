/**
 * Example hardened version of the tealkin-proxy Cloudflare Worker.
 * This file is NOT wired into the site — it's a reference for you to
 * adapt and paste into the actual Worker (Cloudflare dashboard or your
 * separate Worker repo), since that code does not live in this repository.
 *
 * What it adds on top of a bare "forward to DeepSeek" proxy:
 *   1. Origin allow-list — only your own domains can call it.
 *   2. Payload size cap — rejects huge bodies before they reach the AI API.
 *   3. Per-IP rate limiting using Cloudflare KV (a free namespace is enough).
 *   4. CORS headers scoped to your allow-list instead of '*'.
 *
 * Requires: a KV namespace bound as RATE_LIMIT_KV, and DEEPSEEK_API_KEY
 * stored as a Worker secret (wrangler secret put DEEPSEEK_API_KEY).
 */

const ALLOWED_ORIGINS = new Set([
  'https://tealkin.com',
  'https://www.tealkin.com',
]);

const MAX_BODY_BYTES = 20_000;       // reject payloads bigger than this
const RATE_LIMIT_MAX = 20;            // max requests
const RATE_LIMIT_WINDOW_SECONDS = 600; // ...per 10 minutes, per IP

function corsHeaders(origin) {
  const allowed = ALLOWED_ORIGINS.has(origin) ? origin : ALLOWED_ORIGINS.values().next().value;
  return {
    'Access-Control-Allow-Origin': allowed,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Vary': 'Origin',
  };
}

async function checkRateLimit(env, ip) {
  const key = `rl:${ip}`;
  const current = await env.RATE_LIMIT_KV.get(key);
  const count = current ? parseInt(current, 10) : 0;

  if (count >= RATE_LIMIT_MAX) {
    return false;
  }

  await env.RATE_LIMIT_KV.put(key, String(count + 1), {
    expirationTtl: RATE_LIMIT_WINDOW_SECONDS,
  });
  return true;
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const headers = corsHeaders(origin);

    // Preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers });
    }

    if (request.method !== 'POST') {
      return new Response('Method not allowed', { status: 405, headers });
    }

    // 1. Origin allow-list — block anyone calling this from curl/Postman/other sites
    if (!ALLOWED_ORIGINS.has(origin)) {
      return new Response('Forbidden', { status: 403, headers });
    }

    // 2. Payload size cap — checked via Content-Length before reading the body
    const contentLength = parseInt(request.headers.get('Content-Length') || '0', 10);
    if (contentLength > MAX_BODY_BYTES) {
      return new Response('Payload too large', { status: 413, headers });
    }

    // 3. Per-IP rate limit
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const allowed = await checkRateLimit(env, ip);
    if (!allowed) {
      return new Response('Too many requests, slow down.', { status: 429, headers });
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return new Response('Invalid JSON', { status: 400, headers });
    }

    // Defensive re-check on the actual parsed body, not just the header
    if (JSON.stringify(body).length > MAX_BODY_BYTES) {
      return new Response('Payload too large', { status: 413, headers });
    }

    const upstream = await fetch('https://api.deepseek.com/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${env.DEEPSEEK_API_KEY}`,
      },
      body: JSON.stringify(body),
    });

    const responseBody = await upstream.text();
    return new Response(responseBody, {
      status: upstream.status,
      headers: { ...headers, 'Content-Type': 'application/json' },
    });
  },
};
