/**
 * tealkin-proxy Worker — v2
 * Two routes:
 *   POST /        — AI proxy to DeepSeek (unchanged behavior from v1)
 *   POST /scrape  — fetches a public https page server-side, returns clean text
 *                   so the reputation diagnostic can analyze what actually exists online.
 *
 * Shared protections: Origin allow-list, per-IP rate limit (RATE_LIMIT_KV binding),
 * payload caps. Paste this over the current Worker code and Deploy.
 */

const ALLOWED_ORIGINS = new Set([
  'https://tealkin.com',
  'https://www.tealkin.com',
]);

const MAX_BODY_BYTES = 60_000;           // diagnostic prompts include scraped site text
const RATE_LIMIT_MAX = 30;               // slightly higher: diagnostic uses several calls
const RATE_LIMIT_WINDOW_SECONDS = 600;

const SCRAPE_MAX_HTML = 500_000;          // read at most 500KB of HTML
const SCRAPE_MAX_TEXT = 15_000;           // return at most 15KB of clean text

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

// ── SSRF guard: only public https hosts ─────────────────────────────
function isSafeTarget(raw) {
  let u;
  try { u = new URL(raw); } catch { return false; }
  if (u.protocol !== 'https:') return false;
  const host = u.hostname.toLowerCase();
  if (host === 'localhost' || host.endsWith('.local') || host.endsWith('.internal')) return false;
  // reject raw IPv4/IPv6 hosts entirely — public sites have hostnames
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return false;
  if (host.includes(':') || host.startsWith('[')) return false;
  // don't let the tool scrape the worker itself
  if (host.endsWith('.workers.dev')) return false;
  return true;
}

function htmlToText(html) {
  const title = (html.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1] || '';
  const metaDesc = (html.match(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']*)["']/i)
                 || html.match(/<meta[^>]+content=["']([^"']*)["'][^>]+name=["']description["']/i)
                 || [])[1] || '';
  let text = html
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<noscript[\s\S]*?<\/noscript>/gi, ' ')
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&#\d+;|&[a-z]+;/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  return {
    title: title.replace(/\s+/g, ' ').trim().slice(0, 300),
    description: metaDesc.trim().slice(0, 500),
    text: text.slice(0, SCRAPE_MAX_TEXT),
  };
}

async function handleScrape(request, headers) {
  let body;
  try { body = await request.json(); } catch {
    return new Response(JSON.stringify({ error: 'Invalid JSON' }), { status: 400, headers });
  }
  const target = String(body.url || '').trim();
  if (!isSafeTarget(target)) {
    return new Response(JSON.stringify({ error: 'Invalid or unsupported URL. Use a public https:// address.' }), { status: 400, headers });
  }
  let resp;
  try {
    resp = await fetch(target, {
      redirect: 'follow',
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; TealKinDiagnostic/1.0; +https://tealkin.com)',
        'Accept': 'text/html,application/xhtml+xml',
        'Accept-Language': 'es-MX,es;q=0.9,en;q=0.8',
      },
      cf: { cacheTtl: 300 },
    });
  } catch {
    return new Response(JSON.stringify({ error: 'Could not reach that site.' }), { status: 502, headers });
  }
  if (!resp.ok) {
    return new Response(JSON.stringify({ error: `Site responded with status ${resp.status}.` }), { status: 502, headers });
  }
  const ctype = resp.headers.get('Content-Type') || '';
  if (!ctype.includes('text/html') && !ctype.includes('application/xhtml')) {
    return new Response(JSON.stringify({ error: 'That URL is not an HTML page.' }), { status: 415, headers });
  }
  // read up to SCRAPE_MAX_HTML
  const reader = resp.body.getReader();
  const decoder = new TextDecoder();
  let html = '';
  while (html.length < SCRAPE_MAX_HTML) {
    const { done, value } = await reader.read();
    if (done) break;
    html += decoder.decode(value, { stream: true });
  }
  try { await reader.cancel(); } catch {}

  const extracted = htmlToText(html);
  if (!extracted.text || extracted.text.length < 100) {
    return new Response(JSON.stringify({
      error: 'This page has very little readable text (it may load content with JavaScript or block bots).',
      title: extracted.title,
    }), { status: 422, headers });
  }
  return new Response(JSON.stringify({
    url: target,
    title: extracted.title,
    description: extracted.description,
    text: extracted.text,
  }), { status: 200, headers: { ...headers, 'Content-Type': 'application/json' } });
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
    if (!ALLOWED_ORIGINS.has(origin)) {
      return new Response('Forbidden', { status: 403, headers });
    }

    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const allowed = await checkRateLimit(env, ip);
    if (!allowed) {
      return new Response('Too many requests, slow down.', { status: 429, headers });
    }

    const path = new URL(request.url).pathname;

    if (path === '/scrape') {
      return handleScrape(request, { ...headers, 'Content-Type': 'application/json' });
    }

    // ── default route: AI proxy (unchanged) ──
    const body = await request.text();
    if (body.length > MAX_BODY_BYTES) {
      return new Response('Payload too large', { status: 413, headers });
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
