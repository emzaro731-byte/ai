# AI API Key Server

A small Express API for generating, validating, and revoking API keys.

## Endpoints

- `GET /health` — health check
- `POST /api/keys` — create a key (requires `x-admin-secret`)
- `POST /api/keys/validate` — validate a key
- `POST /api/keys/revoke` — revoke a key (requires `x-admin-secret`)

## Run locally

```bash
npm install
cp .env.example .env
# Set ADMIN_SECRET in .env
npm start
```

## Create a key

```bash
curl -X POST http://localhost:3000/api/keys \
  -H 'Content-Type: application/json' \
  -H 'x-admin-secret: YOUR_ADMIN_SECRET' \
  -d '{"name":"flutter-app"}'
```

The generated API key is returned once. Only its SHA-256 hash is stored in memory.

## Important production note

This starter uses an in-memory Map, so keys disappear when the server restarts. For production, move the key records to Supabase/Postgres and keep `ADMIN_SECRET` in the hosting provider's secret/environment settings. Never commit real API keys or admin secrets to Git.
