const keys = new Map();
const rateBuckets = new Map();

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type, x-api-key, x-admin-secret',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
};

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders, ...extraHeaders },
  });
}

function generateApiKey() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return `ai_${Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')}`;
}

async function hashKey(key) {
  const data = new TextEncoder().encode(key);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

function requireAdmin(request, env) {
  const supplied = request.headers.get('x-admin-secret');
  return Boolean(env.ADMIN_SECRET && supplied && supplied === env.ADMIN_SECRET);
}

async function getClientKey(request) {
  const key = request.headers.get('x-api-key');
  if (!key || !key.startsWith('ai_')) return null;
  return keys.get(await hashKey(key)) || null;
}

async function requireApiKey(request) {
  const record = await getClientKey(request);
  if (!record || record.revoked) return null;
  if (record.expiresAt && Date.now() >= Date.parse(record.expiresAt)) {
    record.revoked = true;
    return null;
  }
  return record;
}

function rateLimit(record, limit = 60, windowMs = 60_000) {
  const now = Date.now();
  const key = record.id;
  let bucket = rateBuckets.get(key);
  if (!bucket || now - bucket.startedAt >= windowMs) {
    bucket = { startedAt: now, count: 0 };
    rateBuckets.set(key, bucket);
  }
  bucket.count += 1;
  return {
    allowed: bucket.count <= limit,
    remaining: Math.max(0, limit - bucket.count),
    resetIn: Math.max(0, windowMs - (now - bucket.startedAt)),
  };
}

function requireOpenAI(env) {
  return Boolean(env.OPENAI_API_KEY);
}

async function openai(path, env, options = {}) {
  const base = env.OPENAI_BASE_URL || 'https://api.openai.com/v1';
  return fetch(`${base}${path}`, {
    ...options,
    headers: {
      Authorization: `Bearer ${env.OPENAI_API_KEY}`,
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  });
}

async function proxyJson(response) {
  const text = await response.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = { raw: text };
  }
  return json(body, response.status);
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders });

    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'GET' && path === '/health') {
      return json({
        ok: true,
        service: 'ai-api-key-server',
        platform: 'cloudflare-workers',
        openaiConfigured: Boolean(env.OPENAI_API_KEY),
        keySecurity: 'hashed-expiring-rate-limited',
      });
    }

    if (request.method === 'GET' && path === '/api/models') {
      const clientKey = await requireApiKey(request);
      if (!clientKey) return json({ error: 'Invalid, revoked, or expired API key' }, 401);
      const limit = rateLimit(clientKey, 60);
      if (!limit.allowed) return json({ error: 'Rate limit exceeded', retryAfterMs: limit.resetIn }, 429, { 'Retry-After': String(Math.ceil(limit.resetIn / 1000)) });
      if (!requireOpenAI(env)) return json({ error: 'OPENAI_API_KEY is not configured on the server' }, 503);
      try {
        return proxyJson(await openai('/models', env, { method: 'GET' }));
      } catch (error) {
        return json({ error: error.message }, 502);
      }
    }

    if (request.method === 'POST' && path === '/api/keys') {
      if (!requireAdmin(request, env)) return json({ error: 'Unauthorized' }, 401);
      let body = {};
      try { body = await request.json(); } catch {}
      const key = generateApiKey();
      const id = crypto.randomUUID();
      const name = typeof body?.name === 'string' ? body.name.trim().slice(0, 100) : 'default';
      const days = Number.isFinite(Number(body?.expiresInDays)) ? Math.min(Math.max(Number(body.expiresInDays), 1), 3650) : 365;
      const expiresAt = new Date(Date.now() + days * 86_400_000).toISOString();
      keys.set(await hashKey(key), {
        id,
        name,
        createdAt: new Date().toISOString(),
        expiresAt,
        revoked: false,
      });
      return json({ id, name, apiKey: key, expiresAt }, 201);
    }

    if (request.method === 'POST' && path === '/api/keys/validate') {
      let body = {};
      try { body = await request.json(); } catch {}
      const key = typeof body?.apiKey === 'string' ? body.apiKey : '';
      if (!key) return json({ valid: false, error: 'apiKey is required' }, 400);
      const record = keys.get(await hashKey(key));
      if (!record || record.revoked || (record.expiresAt && Date.now() >= Date.parse(record.expiresAt))) return json({ valid: false }, 401);
      return json({ valid: true, id: record.id, name: record.name, expiresAt: record.expiresAt });
    }

    if (request.method === 'POST' && path === '/api/keys/revoke') {
      if (!requireAdmin(request, env)) return json({ error: 'Unauthorized' }, 401);
      let body = {};
      try { body = await request.json(); } catch {}
      const key = typeof body?.apiKey === 'string' ? body.apiKey : '';
      if (!key) return json({ error: 'apiKey is required' }, 400);
      const keyHash = await hashKey(key);
      const record = keys.get(keyHash);
      if (!record) return json({ error: 'API key not found' }, 404);
      record.revoked = true;
      return json({ revoked: true, id: record.id });
    }

    const clientKey = await requireApiKey(request);
    if (!clientKey) return json({ error: 'Invalid, revoked, or expired API key' }, 401);

    const limit = rateLimit(clientKey, 60);
    if (!limit.allowed) {
      return json({ error: 'Rate limit exceeded', retryAfterMs: limit.resetIn }, 429, {
        'Retry-After': String(Math.ceil(limit.resetIn / 1000)),
      });
    }

    if (!requireOpenAI(env)) return json({ error: 'OPENAI_API_KEY is not configured on the server' }, 503);

    if (request.method === 'POST' && path === '/api/chat') {
      try {
        const body = await request.json();
        const { model = 'gpt-5.6-luna', input, messages, ...options } = body || {};
        const payload = messages ? { model, messages, ...options } : { model, input, ...options };
        return proxyJson(await openai('/responses', env, { method: 'POST', body: JSON.stringify(payload) }));
      } catch (error) {
        return json({ error: error.message }, 502);
      }
    }

    if (request.method === 'POST' && path === '/api/images/generate') {
      try {
        const body = await request.json();
        const { model = 'gpt-image-2', prompt, ...options } = body || {};
        if (!prompt) return json({ error: 'prompt is required' }, 400);
        return proxyJson(await openai('/images/generations', env, { method: 'POST', body: JSON.stringify({ model, prompt, ...options }) }));
      } catch (error) {
        return json({ error: error.message }, 502);
      }
    }

    if (request.method === 'POST' && path === '/api/audio/speech') {
      try {
        const body = await request.json();
        const { model = 'gpt-4o-mini-tts', input, voice = 'alloy', ...options } = body || {};
        if (!input) return json({ error: 'input is required' }, 400);
        const response = await openai('/audio/speech', env, { method: 'POST', body: JSON.stringify({ model, input, voice, ...options }) });
        return new Response(await response.arrayBuffer(), {
          status: response.status,
          headers: { 'Content-Type': response.headers.get('content-type') || 'audio/mpeg', ...corsHeaders },
        });
      } catch (error) {
        return json({ error: error.message }, 502);
      }
    }

    if (request.method === 'POST' && path === '/api/videos') {
      try {
        return proxyJson(await openai('/videos', env, { method: 'POST', body: await request.text() }));
      } catch (error) {
        return json({ error: error.message }, 502);
      }
    }

    if (request.method === 'GET' && path.startsWith('/api/videos/')) {
      try {
        const id = encodeURIComponent(path.slice('/api/videos/'.length));
        return proxyJson(await openai(`/videos/${id}`, env, { method: 'GET' }));
      } catch (error) {
        return json({ error: error.message }, 502);
      }
    }

    return json({ error: 'Not found' }, 404);
  },
};
