/**
 * tealkin-proxy Worker — v3
 * Routes:
 *   POST /          — AI proxy to DeepSeek (analyst)
 *   POST /scrape    — fetches a public https page server-side, returns clean text
 *   POST /research  — live web research via Gemini + Google Search grounding:
 *                     what is being said online about a brand (reviews, news,
 *                     social mentions indexed by Google).
 *
 * Secrets required: DeepSeek (existing), Gemini (new — free key from aistudio.google.com).
 * Binding required: RATE_LIMIT_KV (existing).
 * Shared protections: Origin allow-list, per-IP rate limit, payload caps.
 * Paste this over the current Worker code and Deploy.
 */

const ALLOWED_ORIGINS = new Set([
  'https://tealkin.com',
  'https://www.tealkin.com',
]);

const MAX_BODY_BYTES = 60_000;
const RATE_LIMIT_MAX = 40;
const RATE_LIMIT_WINDOW_SECONDS = 600;

const SCRAPE_MAX_HTML = 500_000;
const SCRAPE_MAX_TEXT = 15_000;

const BROWSER_HEADERS = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
  'Accept-Language': 'es-MX,es;q=0.9,en;q=0.8',
  'Sec-Fetch-Dest': 'document',
  'Sec-Fetch-Mode': 'navigate',
  'Sec-Fetch-Site': 'none',
  'Sec-Fetch-User': '?1',
  'Upgrade-Insecure-Requests': '1',
  'Cache-Control': 'no-cache',
};
const BOT_HEADERS = {
  'User-Agent': 'Mozilla/5.0 (compatible; TealKinDiagnostic/1.0; +https://tealkin.com)',
  'Accept': 'text/html,application/xhtml+xml',
  'Accept-Language': 'es-MX,es;q=0.9,en;q=0.8',
};

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
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return false;
  if (host.includes(':') || host.startsWith('[')) return false;
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

async function fetchPage(target, headerSet) {
  return fetch(target, {
    redirect: 'follow',
    headers: headerSet,
    cf: { cacheTtl: 300 },
  });
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
  let resp = null;
  // try browser-like headers first, then bot headers as fallback
  for (const headerSet of [BROWSER_HEADERS, BOT_HEADERS]) {
    try {
      resp = await fetchPage(target, headerSet);
      if (resp.ok) break;
    } catch { resp = null; }
  }
  if (!resp) {
    return new Response(JSON.stringify({ error: 'Could not reach that site.' }), { status: 502, headers });
  }
  if (!resp.ok) {
    return new Response(JSON.stringify({ error: `Site responded with status ${resp.status}.` }), { status: 502, headers });
  }
  const ctype = resp.headers.get('Content-Type') || '';
  if (!ctype.includes('text/html') && !ctype.includes('application/xhtml')) {
    return new Response(JSON.stringify({ error: 'That URL is not an HTML page.' }), { status: 415, headers });
  }
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
  }), { status: 200, headers });
}

// ── /research: Gemini + Google Search grounding ──────────────────────
async function handleResearch(request, env, headers) {
  let body;
  try { body = await request.json(); } catch {
    return new Response(JSON.stringify({ error: 'Invalid JSON' }), { status: 400, headers });
  }
  const brand = String(body.brand || '').trim().slice(0, 120);
  const location = String(body.location || '').trim().slice(0, 120);
  const sector = String(body.sector || '').trim().slice(0, 120);
  const person = String(body.person || '').trim().slice(0, 120);
  const topic = String(body.topic || '').trim().slice(0, 200);
  const mode = body.mode === 'interview' ? 'interview' : 'diagnostic';
  const lang = body.lang === 'en' ? 'en' : 'es';
  if (brand.length < 2) {
    return new Response(JSON.stringify({ error: 'Missing brand name.' }), { status: 400, headers });
  }
  if (!env.Gemini) {
    return new Response(JSON.stringify({ error: 'Research is not configured.' }), { status: 503, headers });
  }

  let prompt;
  if (mode === 'interview') {
    prompt = lang === 'es'
      ? `Eres el investigador de un programa periodístico preparando una entrevista dura. El entrevistado es ${person ? '"' + person + '", ' : ''}de la organización "${brand}"${location ? ' (' + location + ')' : ''}, y el tema declarado de la entrevista es: "${topic}". Investiga en la web y arma un dossier con material que un periodista incisivo usaría para incomodarlo: (1) crisis, controversias o quejas pasadas de la organización o su sector, (2) noticias RECIENTES sobre la organización, sus competidores o su industria, (3) eventos de contexto actual que puedan cruzarse con el tema (coyuntura económica, política, eventos como el Mundial, tendencias), (4) cualquier declaración pública previa de la organización o la persona que pueda contrastarse. Presenta 4-6 puntos concretos y citables, cada uno con su fuente. Si sobre algo no hay información, dilo — no inventes nada. Responde en español.`
      : `You are the researcher for a journalism program preparing a tough interview. The interviewee is ${person ? '"' + person + '", ' : ''}from the organization "${brand}"${location ? ' (' + location + ')' : ''}, and the declared interview topic is: "${topic}". Research the web and build a dossier with material an incisive journalist would use to make them uncomfortable: (1) past crises, controversies or complaints involving the organization or its sector, (2) RECENT news about the organization, its competitors or its industry, (3) current-context events that could intersect with the topic (economy, politics, events like the World Cup, trends), (4) any prior public statements by the organization or the person that could be contrasted. Present 4-6 concrete, quotable points, each with its source. If information doesn't exist on something, say so — invent nothing. Respond in English.`;
  } else {
    prompt = lang === 'es'
      ? `Investiga en la web qué se dice EN LÍNEA sobre el negocio "${brand}"${location ? ' ubicado en ' + location : ''}${sector ? ' (sector: ' + sector + ')' : ''}. Busca: reseñas de clientes (Google, TripAdvisor, etc.), menciones en redes sociales y noticias, quejas o controversias, y cómo se percibe su reputación en general. Resume tus hallazgos en 3-5 párrafos concretos, citando de dónde viene cada dato. Si encuentras poca o ninguna información, dilo explícitamente — eso también es un hallazgo relevante (invisibilidad digital). No inventes nada. Responde en español.`
      : `Research the web for what is being said ONLINE about the business "${brand}"${location ? ' located in ' + location : ''}${sector ? ' (sector: ' + sector + ')' : ''}. Look for: customer reviews (Google, TripAdvisor, etc.), social media mentions and news, complaints or controversies, and overall reputation perception. Summarize findings in 3-5 concrete paragraphs, citing where each fact comes from. If you find little or no information, say so explicitly — that is itself a relevant finding (digital invisibility). Do not invent anything. Respond in English.`;
  }

  const callModel = async (model) => fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-goog-api-key': env.Gemini,
      },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        tools: [{ google_search: {} }],
        generationConfig: { temperature: 0.3, maxOutputTokens: 2048 },
      }),
    }
  );

  // model availability varies by account/API version. Try the model that
  // worked last time (cached in KV), then known names, then ask Google
  // directly which models this key can use (ListModels) and cache the pick.
  const cached = await env.RATE_LIMIT_KV.get('gemini_model');
  // prefer the 'latest' aliases (Google keeps them pointing at live models);
  // pinned versions get retired and start returning 404
  const MODELS = [...new Set([cached, 'gemini-flash-latest', 'gemini-2.5-flash', 'gemini-2.0-flash'].filter(Boolean))];
  let resp = null;
  let usedModel = '';
  let lastErr = '';
  let cachedFailed = false;

  for (const model of MODELS) {
    try { resp = await callModel(model); } catch { lastErr = 'unreachable'; resp = null; continue; }
    if (resp.ok) { usedModel = model; break; }
    if (model === cached) cachedFailed = true;
    try {
      const eBody = await resp.json();
      lastErr = resp.status + ' ' + ((eBody.error && eBody.error.message) || '').slice(0, 200);
    } catch { lastErr = String(resp.status); }
    resp = null;
  }
  // the cached model was retired by Google — forget it so it's never tried again
  if (cachedFailed) { try { await env.RATE_LIMIT_KV.delete('gemini_model'); } catch {} }

  // self-configure: ask Google what models this key actually has
  if (!resp) {
    try {
      const listResp = await fetch('https://generativelanguage.googleapis.com/v1beta/models?pageSize=100', {
        headers: { 'x-goog-api-key': env.Gemini },
      });
      if (listResp.ok) {
        const list = await listResp.json();
        const candidates = (list.models || [])
          .filter(m => (m.supportedGenerationMethods || []).includes('generateContent'))
          .map(m => m.name.replace(/^models\//, ''))
          // prefer flash-class 'latest' aliases; penalize pinned -00X versions
          // and lite variants (both get retired and 404), previews, and non-chat models
          .sort((a, b) => {
            const scoreOf = n =>
              (n.includes('flash') ? 0 : 3) +
              (n.includes('latest') ? -2 : 0) +
              (/-\d{3}$/.test(n) ? 2 : 0) +
              (n.includes('lite') ? 1 : 0) +
              (n.includes('preview') || n.includes('exp') ? 1 : 0) +
              (n.includes('thinking') || n.includes('tts') || n.includes('image') || n.includes('embed') || n.includes('audio') || n.includes('live') ? 8 : 0);
            return scoreOf(a) - scoreOf(b);
          });
        for (const model of candidates.slice(0, 6)) {
          try { resp = await callModel(model); } catch { resp = null; continue; }
          if (resp.ok) { usedModel = model; break; }
          try {
            const eBody = await resp.json();
            lastErr = resp.status + ' ' + ((eBody.error && eBody.error.message) || '').slice(0, 200);
          } catch { lastErr = String(resp.status); }
          resp = null;
        }
      } else {
        try {
          const eBody = await listResp.json();
          lastErr = 'ListModels ' + listResp.status + ' ' + ((eBody.error && eBody.error.message) || '').slice(0, 200);
        } catch { lastErr = 'ListModels ' + listResp.status; }
      }
    } catch { lastErr = lastErr || 'ListModels unreachable'; }
  }

  if (!resp) {
    return new Response(JSON.stringify({ error: 'Research failed: ' + (lastErr || 'no model available') }), { status: 502, headers });
  }
  if (usedModel && usedModel !== cached) {
    try { await env.RATE_LIMIT_KV.put('gemini_model', usedModel); } catch {}
  }
  const data = await resp.json();
  const cand = data.candidates && data.candidates[0];
  const summary = cand && cand.content && cand.content.parts
    ? cand.content.parts.map(p => p.text || '').join('\n').trim()
    : '';
  if (!summary) {
    return new Response(JSON.stringify({ error: 'Empty research result.' }), { status: 502, headers });
  }
  // grounding sources (deduped by URL)
  const chunks = (cand.groundingMetadata && cand.groundingMetadata.groundingChunks) || [];
  const seen = new Set();
  const sources = [];
  for (const c of chunks) {
    const w = c.web || {};
    if (w.uri && !seen.has(w.uri)) {
      seen.add(w.uri);
      sources.push({ title: (w.title || w.uri).slice(0, 200), url: w.uri });
    }
    if (sources.length >= 8) break;
  }
  return new Response(JSON.stringify({ brand, summary: summary.slice(0, 12_000), sources }), { status: 200, headers });
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const headers = corsHeaders(origin);
    const jsonHeaders = { ...headers, 'Content-Type': 'application/json' };

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
    if (path === '/scrape') return handleScrape(request, jsonHeaders);
    if (path === '/research') return handleResearch(request, env, jsonHeaders);

    // ── default route: AI proxy (analyst) ──
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
      headers: jsonHeaders,
    });
  },
};
