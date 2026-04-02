import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { bodyLimit } from 'hono/body-limit';
import { timeout } from 'hono/timeout';
import { secureHeaders } from 'hono/secure-headers';
import { bearerAuth } from 'hono/bearer-auth';
import { randomUUIDv7 } from "bun";
import Database from "bun:sqlite";
import { mkdirSync, existsSync } from "fs";

// DB setup + INDEX
const db = new Database("api.db");

db.run(`
  CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE,
    created_at INTEGER,
    last_used INTEGER,  -- NEW: For expiry/stats
    requests INTEGER DEFAULT 0
  )
`);

db.run("CREATE INDEX IF NOT EXISTS idx_keys ON api_keys(key)");

// Helper: Save key
function saveApiKey(key: string) {
  const now = Date.now()
  db.run("INSERT INTO api_keys (key, created_at, last_used) VALUES (?, ?, ?)", [key, now, now]);
}

// Generate a unique API key using UUIDv7 and save it to the database
function generateAPIKey(prefix = 'zh-api'): string {
  const UUID = randomUUIDv7()
  const key = `${prefix}-${UUID}`
  saveApiKey(key)
  return key
};

// Middleware: Check for API key in Authorization header and validate against DB
const authMiddleware = async (c, next) => {
  const auth = c.req.header('Authorization');
  if (!auth?.startsWith('Bearer ')) {
    return c.json({ error: 'Missing or invalid Authorization header' }, 401);
  }
  const token = auth.slice(7);
  const row = db.prepare("SELECT * FROM api_keys WHERE key = ?").get(token) as any;
  if (!row) {
    return c.json({ error: 'Invalid API key' }, 401);
  }
  let requests = row.requests || 0;

  const now = Date.now()
  const ONE_DAY = 86400000

  if (now - row.last_used > ONE_DAY) {
    requests = 0;
    db.run("UPDATE api_keys SET requests = 0 WHERE key = ?", [token])
  }

  if (requests >= 100) {
    return c.json({ error: 'Rate limit exceeded (100 reqs/day)' }, 429)
  }

  db.run("UPDATE api_keys SET requests = requests + 1, last_used = ? WHERE key = ?", [now, token]);
  c.set('apiKeyRequests', requests + 1);  // For logging
  await next();
};

type TranslateRequest = {
  text: string
};

type OpenRouterChoice = {
  message?: {
    content?: string
  }
};

type OpenRouterResponse = {
  choices?: OpenRouterChoice[]
};

const app = new Hono();
const API_KEY = process.env.API_KEY;

async function callOpenRouter(body: TranslateRequest) {
  const prompt = `
You are a translation engine.
Translate the given English text into Simplified Chinese, Traditional Chinese, and Pinyin (with tone marks).
Return ONLY valid JSON, no explanations.
Format:
{
  "simplified": "...",
  "traditional": "...",
  "pinyin": "..."
}
Text: "${body.text}"
`

  const res = await fetch('https://openrouter.ai/api/v1/chat/completions', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: 'qwen/qwen3.5-flash-02-23',
      reasoning: { enabled: false },
      temperature: 0.2,
      messages: [
        {
          role: 'user',
          content: prompt,
        },
      ],
    }),
  });

  if (!res.ok) {
    const text = await res.text()
    console.error('OpenRouter error:', text)
    return { error: `Upstream error (${res.status})` }
  }

  const data = (await res.json()) as OpenRouterResponse
  const rawText = data.choices?.[0]?.message?.content ?? '{}'

  try {
    return JSON.parse(rawText) as Record<string, string>
  } catch (e) {
    console.error('Parse error:', rawText)
    return { error: 'Invalid model response' }
  }

};

// CORS - Who can access this API and how
app.use(
  '/*',
  cors({
    origin: '*',
    allowHeaders: ['Content-Type'],
    allowMethods: ['GET', 'POST'],
    exposeHeaders: [],
    maxAge: 86400,
  })
);

// Logger - Log incoming requests and responses (for stats :)
app.use(logger());

app.use('/api/translate', timeout(60000)); // Timeout - Set a maximum time limit of 60 seconds for the translation process

app.use(secureHeaders()); // Secure Headers - Add security-related HTTP headers to responses to protect against common web vulnerabilities


app.post('/api/translate',
  authMiddleware,
  bodyLimit({ // Limit the size of incoming request bodies to prevent abuse
    maxSize: 50 * 1024, // 50kb
    onError: (c) => {
      return c.text('overflow :(', 413)
    },
  }), async (c) => {
    const body = (await c.req.json()) as TranslateRequest

    if (!body.text || typeof body.text !== 'string') {
      return c.json({ error: 'Invalid input: text required' }, 400)
    }

    if (body.text.length > 500) {
      return c.json({ error: 'Text too long (max 500 chars)' }, 400)
    }

    const parsed = await callOpenRouter(body)
    return c.json(parsed)
  });

app.post('/api/generate-key', // Add CORS and more for this
  async (c) => {
    const admin = c.req.header('x-admin-key');
    if (admin !== process.env.ADMIN_KEY) {
      return c.json({ error: 'Unauthorized' }, 401)
    }
    const apiKey = generateAPIKey()
    return c.json({ apiKey })
  });

app.get('/api/stats', async (c) => {
  const total = db.prepare("SELECT COUNT(*) as count FROM api_keys").get() as { count: number }
  const usage = db.prepare("SELECT SUM(requests) as total FROM api_keys").get() as { total: number | null }

  return c.json({
    total_keys: total.count,
    total_requests: usage.total || 0
  })
})

export default app;