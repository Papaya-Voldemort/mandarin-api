# Mandarin API

Lightweight Bun + Hono API for signing up, creating API keys, and calling the Mandarin translation endpoint.

## Run

```bash
bun install
bun run dev
```

## Environment

Optional:

```ini
SQLITE_PATH=./data/api.db
HACKCLUB_AI_API_KEY=your_hack_club_ai_key
HACKCLUB_AI_MODEL=qwen/qwen3-32b
# Optional override (default shown):
# HACKCLUB_AI_BASE_URL=https://ai.hackclub.com/proxy/v1
# Test helper only:
# TRANSLATE_MOCK=1
```

## API

- `POST /api/register` — create an account and session
- `POST /api/login` — sign in and create a session
- `POST /api/logout` — invalidate the current session
- `GET /api/me` — current account details
- `GET /api/keys` — list your keys
- `POST /api/keys` — create a key
- `POST /api/keys/:id/revoke` — revoke a key
- `POST /api/translate` — translate text with `x-api-key` (server calls Hack Club AI chat completions)

## Limits

- Auth endpoints: `8` requests per `15` minutes per IP
- Translate endpoint: `120` requests per minute per API key

Open the app at `/` for the dashboard and quick docs.
