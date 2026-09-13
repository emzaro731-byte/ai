require('dotenv').config();

const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json({ limit: '32kb' }));

const PORT = Number(process.env.PORT || 3000);
const ADMIN_SECRET = process.env.ADMIN_SECRET;

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

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'ai-api-key-server' });
});

// Generate a new API key. The plaintext key is returned only once.
app.post('/api/keys', requireAdmin, (req, res) => {
  const key = generateApiKey();
  const id = crypto.randomUUID();
  const keyHash = hashKey(key);
  const name = typeof req.body?.name === 'string' ? req.body.name.trim().slice(0, 100) : 'default';

  keys.set(keyHash, {
    id,
    name,
    createdAt: new Date().toISOString(),
    revoked: false
  });

  res.status(201).json({ id, name, apiKey: key });
});

// Validate an API key.
app.post('/api/keys/validate', (req, res) => {
  const key = typeof req.body?.apiKey === 'string' ? req.body.apiKey : '';
  if (!key) return res.status(400).json({ valid: false, error: 'apiKey is required' });

  const record = keys.get(hashKey(key));
  if (!record || record.revoked) {
    return res.status(401).json({ valid: false });
  }

  res.json({ valid: true, id: record.id, name: record.name });
});

// Revoke an API key without accepting the key itself in a URL.
app.post('/api/keys/revoke', requireAdmin, (req, res) => {
  const key = typeof req.body?.apiKey === 'string' ? req.body.apiKey : '';
  if (!key) return res.status(400).json({ error: 'apiKey is required' });

  const keyHash = hashKey(key);
  const record = keys.get(keyHash);
  if (!record) return res.status(404).json({ error: 'API key not found' });

  record.revoked = true;
  res.json({ revoked: true, id: record.id });
});

app.use((_req, res) => res.status(404).json({ error: 'Not found' }));

app.listen(PORT, () => {
  console.log(`API key server listening on port ${PORT}`);
});
