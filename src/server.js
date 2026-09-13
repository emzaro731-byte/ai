require('dotenv').config();

const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json({ limit: '10mb' }));

const PORT = Number(process.env.PORT || 3000);
const ADMIN_SECRET = process.env.ADMIN_SECRET;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const OPENAI_BASE_URL = process.env.OPENAI_BASE_URL || 'https://api.openai.com/v1';

// Demo in-memory store. For production, replace this Map with Supabase/Postgres.
const keys = new Map();

function generateApiKey() {
  return `ai_${crypto.randomBytes(32).toString('hex')}`;
}

function hashKey(key) {
  return crypto.createHash('sha256').update(key).digest('hex');
}

function requireAdmin(req, res, next) {
  if (!ADMIN_SECRET || req.get('x-admin-secret') !== ADMIN_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

function requireApiKey(req, res, next) {
  const key = req.get('x-api-key');
  const record = key ? keys.get(hashKey(key)) : null;
  if (!record || record.revoked) return res.status(401).json({ error: 'Invalid API key' });
  req.clientKey = record;
  next();
}

function requireOpenAI(req, res, next) {
  if (!OPENAI_API_KEY) {
    return res.status(503).json({ error: 'OPENAI_API_KEY is not configured on the server' });
  }
  next();
}

async function openai(path, options = {}) {
  const response = await fetch(`${OPENAI_BASE_URL}${path}`, {
    ...options,
    headers: {
      Authorization: `Bearer ${OPENAI_API_KEY}`,
      'Content-Type': 'application/json',
      ...(options.headers || {})
    }
  });

  const text = await response.text();
  let body;
  try { body = JSON.parse(text); } catch { body = { raw: text }; }
  return { status: response.status, body };
}

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'ai-api-key-server', openaiConfigured: Boolean(OPENAI_API_KEY) });
});

// Return the models available to the configured OpenAI account.
app.get('/api/models', requireApiKey, requireOpenAI, async (_req, res) => {
  try {
    const result = await openai('/models', { method: 'GET' });
    res.status(result.status).json(result.body);
  } catch (error) {
    res.status(502).json({ error: error.message });
  }
});

// Generate a new client API key. The plaintext key is returned only once.
app.post('/api/keys', requireAdmin, (req, res) => {
  const key = generateApiKey();
  const id = crypto.randomUUID();
  const keyHash = hashKey(key);
  const name = typeof req.body?.name === 'string' ? req.body.name.trim().slice(0, 100) : 'default';

  keys.set(keyHash, { id, name, createdAt: new Date().toISOString(), revoked: false });
  res.status(201).json({ id, name, apiKey: key });
});

app.post('/api/keys/validate', (req, res) => {
  const key = typeof req.body?.apiKey === 'string' ? req.body.apiKey : '';
  if (!key) return res.status(400).json({ valid: false, error: 'apiKey is required' });
  const record = keys.get(hashKey(key));
  if (!record || record.revoked) return res.status(401).json({ valid: false });
  res.json({ valid: true, id: record.id, name: record.name });
});

app.post('/api/keys/revoke', requireAdmin, (req, res) => {
  const key = typeof req.body?.apiKey === 'string' ? req.body.apiKey : '';
  if (!key) return res.status(400).json({ error: 'apiKey is required' });
  const keyHash = hashKey(key);
  const record = keys.get(keyHash);
  if (!record) return res.status(404).json({ error: 'API key not found' });
  record.revoked = true;
  res.json({ revoked: true, id: record.id });
});

// Universal text/image chat. The model is supplied by the client, so GPT-5 and
// other models available to the configured OpenAI account can be selected.
app.post('/api/chat', requireApiKey, requireOpenAI, async (req, res) => {
  try {
    const { model = 'gpt-5.6-luna', input, messages, ...options } = req.body || {};
    const payload = messages
      ? { model, messages, ...options }
      : { model, input, ...options };
    const result = await openai('/responses', { method: 'POST', body: JSON.stringify(payload) });
    res.status(result.status).json(result.body);
  } catch (error) {
    res.status(502).json({ error: error.message });
  }
});

// Image generation/edit-capable request. Use an image-capable OpenAI model.
app.post('/api/images/generate', requireApiKey, requireOpenAI, async (req, res) => {
  try {
    const { model = 'gpt-image-2', prompt, ...options } = req.body || {};
    if (!prompt) return res.status(400).json({ error: 'prompt is required' });
    const result = await openai('/images/generations', {
      method: 'POST',
      body: JSON.stringify({ model, prompt, ...options })
    });
    res.status(result.status).json(result.body);
  } catch (error) {
    res.status(502).json({ error: error.message });
  }
});

// Text-to-speech endpoint for voice/audio. This is not a music-generation endpoint.
app.post('/api/audio/speech', requireApiKey, requireOpenAI, async (req, res) => {
  try {
    const { model = 'gpt-4o-mini-tts', input, voice = 'alloy', ...options } = req.body || {};
    if (!input) return res.status(400).json({ error: 'input is required' });
    const response = await fetch(`${OPENAI_BASE_URL}/audio/speech`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${OPENAI_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ model, input, voice, ...options })
    });
    const buffer = Buffer.from(await response.arrayBuffer());
    if (!response.ok) {
      return res.status(response.status).send(buffer);
    }
    res.set('Content-Type', response.headers.get('content-type') || 'audio/mpeg');
    res.send(buffer);
  } catch (error) {
    res.status(502).json({ error: error.message });
  }
});

// Video generation proxy. Video jobs are asynchronous; the OpenAI response
// contains the job information that the client can poll according to the API.
app.post('/api/videos', requireApiKey, requireOpenAI, async (req, res) => {
  try {
    const result = await openai('/videos', { method: 'POST', body: JSON.stringify(req.body || {}) });
    res.status(result.status).json(result.body);
  } catch (error) {
    res.status(502).json({ error: error.message });
  }
});

// Fetch a video job/result by ID.
app.get('/api/videos/:id', requireApiKey, requireOpenAI, async (req, res) => {
  try {
    const result = await openai(`/videos/${encodeURIComponent(req.params.id)}`, { method: 'GET' });
    res.status(result.status).json(result.body);
  } catch (error) {
    res.status(502).json({ error: error.message });
  }
});

app.use((_req, res) => res.status(404).json({ error: 'Not found' }));

app.listen(PORT, () => console.log(`AI API server listening on port ${PORT}`));
