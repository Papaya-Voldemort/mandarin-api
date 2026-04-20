import { Hono } from "hono";
import type { Context, Next } from "hono";
import { cors } from "hono/cors";
import { logger } from "hono/logger";
import { bodyLimit } from "hono/body-limit";
import { timeout } from "hono/timeout";
import { secureHeaders } from "hono/secure-headers";
import { serveStatic } from "hono/bun";
import Database from "bun:sqlite";
import { existsSync, mkdirSync } from "fs";
import path from "path";
import crypto from "crypto";

type Variables = {
  userId: number;
  userEmail: string;
};

type AppEnv = {
  Variables: Variables;
};

type UserRow = {
  id: number;
  email: string;
  password_hash: string;
  created_at: number;
};

type SessionRow = {
  id: number;
  user_id: number;
  token: string | null;
  token_hash: string | null;
  created_at: number;
  expires_at: number | null;
};

type ApiKeyRow = {
  id: number;
  user_id: number;
  key: string | null;
  key_hash: string | null;
  label: string | null;
  key_prefix: string | null;
  key_last4: string | null;
  created_at: number;
  last_used: number | null;
  requests: number | null;
  revoked_at: number | null;
};

type RateLimitRow = {
  scope: string;
  window_start: number;
  count: number;
};

type JSONValue = Record<string, unknown>;

const sqlitePath = process.env.SQLITE_PATH || "./data/api.db";
const sqliteDir = path.dirname(sqlitePath);
const SESSION_TTL = 1000 * 60 * 60 * 24 * 30;
const AUTH_WINDOW = 1000 * 60 * 15;
const AUTH_LIMIT = 8;
const API_WINDOW = 1000 * 60;
const API_LIMIT = 120;
const PBKDF2_ITERATIONS = 120000;
const HACKCLUB_AI_BASE_URL = process.env.HACKCLUB_AI_BASE_URL || "https://ai.hackclub.com/proxy/v1";
const HACKCLUB_AI_MODEL = process.env.HACKCLUB_AI_MODEL || "qwen/qwen3-32b";
const HACKCLUB_AI_API_KEY = process.env.HACKCLUB_AI_API_KEY || "";
const TRANSLATE_MOCK = process.env.TRANSLATE_MOCK === "1";

type TranslationResult = {
  simplified: string;
  traditional: string;
  pinyin: string;
  note: string;
};

if (!existsSync(sqliteDir)) {
  mkdirSync(sqliteDir, { recursive: true });
}

const db = new Database(sqlitePath);
db.exec("PRAGMA journal_mode = WAL;");
db.exec("PRAGMA foreign_keys = ON;");

const app = new Hono<AppEnv>();

function now() {
  return Date.now();
}

function sha256(value: string) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function hashPassword(password: string, salt = crypto.randomBytes(16).toString("base64url")) {
  const derived = crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, 32, "sha256").toString(
    "base64url"
  );
  return `pbkdf2_sha256$${PBKDF2_ITERATIONS}$${salt}$${derived}`;
}

function verifyPassword(password: string, encoded: string) {
  const [algorithm, iterationsText, salt, stored] = encoded.split("$");
  if (algorithm !== "pbkdf2_sha256" || !iterationsText || !salt || !stored) {
    return false;
  }

  const iterations = Number(iterationsText);
  if (!Number.isFinite(iterations)) {
    return false;
  }

  const derived = crypto.pbkdf2Sync(password, salt, iterations, 32, "sha256").toString("base64url");
  const storedBuffer = Buffer.from(stored);
  const derivedBuffer = Buffer.from(derived);

  if (storedBuffer.length !== derivedBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(storedBuffer, derivedBuffer);
}

function apiKeyPrefix(key: string) {
  return key.slice(0, 16);
}

function apiKeySuffix(key: string) {
  return key.slice(-4);
}

function sessionToken() {
  return randomToken(32);
}

function newApiKey() {
  return `mk_live_${randomToken(24)}`;
}

function getClientIp(c: Context<AppEnv>) {
  const forwarded = c.req.header("x-forwarded-for");
  return (
    c.req.header("cf-connecting-ip") ||
    c.req.header("x-real-ip") ||
    forwarded?.split(",")[0]?.trim() ||
    "unknown"
  );
}

function ensureColumns(table: string, columns: Record<string, string>) {
  const rows = db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>;
  const existing = new Set(rows.map((row) => row.name));

  for (const [name, definition] of Object.entries(columns)) {
    if (!existing.has(name)) {
      db.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${definition};`);
    }
  }
}

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT UNIQUE,
    token_hash TEXT UNIQUE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    key TEXT UNIQUE,
    key_hash TEXT UNIQUE,
    label TEXT,
    key_prefix TEXT,
    key_last4 TEXT,
    created_at INTEGER NOT NULL,
    last_used INTEGER,
    requests INTEGER DEFAULT 0,
    revoked_at INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS rate_limits (
    scope TEXT PRIMARY KEY,
    window_start INTEGER NOT NULL,
    count INTEGER NOT NULL DEFAULT 0
  );
`);

ensureColumns("sessions", {
  user_id: "INTEGER",
  token: "TEXT",
  token_hash: "TEXT",
  created_at: "INTEGER",
  expires_at: "INTEGER",
});

ensureColumns("api_keys", {
  user_id: "INTEGER",
  key: "TEXT",
  key_hash: "TEXT",
  label: "TEXT",
  key_prefix: "TEXT",
  key_last4: "TEXT",
  created_at: "INTEGER",
  last_used: "INTEGER",
  requests: "INTEGER",
  revoked_at: "INTEGER",
});

db.exec(`
  CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
  CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
  CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);
  CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
  CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
`);

const statements = {
  createUser: db.prepare(
    "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)"
  ),
  findUserByEmail: db.prepare("SELECT * FROM users WHERE email = ? COLLATE NOCASE"),
  findUserById: db.prepare("SELECT * FROM users WHERE id = ?"),
  createSession: db.prepare(
    "INSERT INTO sessions (user_id, token, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)"
  ),
  findSessionByTokenHash: db.prepare("SELECT * FROM sessions WHERE token_hash = ?"),
  findSessionByToken: db.prepare("SELECT * FROM sessions WHERE token = ?"),
  deleteSessionByTokenHash: db.prepare("DELETE FROM sessions WHERE token_hash = ?"),
  createApiKey: db.prepare(
    "INSERT INTO api_keys (user_id, key, key_hash, label, key_prefix, key_last4, created_at, last_used, requests, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, NULL)"
  ),
  findApiKeyByHash: db.prepare("SELECT * FROM api_keys WHERE key_hash = ?"),
  findApiKeyByValue: db.prepare("SELECT * FROM api_keys WHERE key = ?"),
  listApiKeys: db.prepare(
    "SELECT id, label, key_prefix, key_last4, created_at, last_used, requests, revoked_at FROM api_keys WHERE user_id = ? ORDER BY created_at DESC"
  ),
  revokeApiKey: db.prepare(
    "UPDATE api_keys SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL"
  ),
  markApiKeyUsed: db.prepare(
    "UPDATE api_keys SET last_used = ?, requests = COALESCE(requests, 0) + 1 WHERE id = ?"
  ),
  countUsers: db.prepare("SELECT COUNT(*) AS count FROM users"),
  countSessions: db.prepare("SELECT COUNT(*) AS count FROM sessions WHERE expires_at IS NULL OR expires_at > ?"),
  countKeys: db.prepare("SELECT COUNT(*) AS count FROM api_keys WHERE revoked_at IS NULL"),
  countRequests: db.prepare("SELECT COALESCE(SUM(requests), 0) AS total FROM api_keys"),
  upsertRateLimit: db.prepare(
    "INSERT INTO rate_limits (scope, window_start, count) VALUES (?, ?, ?) ON CONFLICT(scope) DO UPDATE SET window_start = excluded.window_start, count = excluded.count"
  ),
  findRateLimit: db.prepare("SELECT * FROM rate_limits WHERE scope = ?"),
};

function rateLimit(scope: string, limit: number, windowMs: number) {
  const currentWindow = Math.floor(now() / windowMs) * windowMs;
  const row = statements.findRateLimit.get(scope) as RateLimitRow | undefined;

  if (!row || row.window_start !== currentWindow) {
    statements.upsertRateLimit.run(scope, currentWindow, 1);
    return {
      allowed: true,
      remaining: limit - 1,
      resetAt: currentWindow + windowMs,
    };
  }

  if (row.count >= limit) {
    return {
      allowed: false,
      remaining: 0,
      resetAt: row.window_start + windowMs,
    };
  }

  statements.upsertRateLimit.run(scope, row.window_start, row.count + 1);
  return {
    allowed: true,
    remaining: limit - row.count - 1,
    resetAt: row.window_start + windowMs,
  };
}

function applyRateLimitHeaders(c: Context<AppEnv>, info: ReturnType<typeof rateLimit>, limit: number) {
  c.header("X-RateLimit-Limit", String(limit));
  c.header("X-RateLimit-Remaining", String(Math.max(info.remaining, 0)));
  c.header("X-RateLimit-Reset", String(Math.ceil(info.resetAt / 1000)));
}

function requireBodyFields(body: JSONValue, fields: string[]) {
  return fields.every((field) => typeof body[field] === "string" && body[field].trim().length > 0);
}

function sanitizeEmail(email: string) {
  return email.trim().toLowerCase();
}

function publicUser(user: UserRow) {
  return {
    id: user.id,
    email: user.email,
    createdAt: user.created_at,
  };
}

function extractJsonObject(text: string) {
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start === -1 || end === -1 || end <= start) {
    return null;
  }
  return text.slice(start, end + 1);
}

function normalizeTranslation(result: Partial<TranslationResult>) {
  return {
    simplified: String(result.simplified || "").trim(),
    traditional: String(result.traditional || "").trim(),
    pinyin: String(result.pinyin || "").trim(),
    note: String(result.note || "").trim() || "Generated by Hack Club AI.",
  };
}

async function translateWithHackClub(text: string) {
  if (TRANSLATE_MOCK) {
    return {
      simplified: "你好",
      traditional: "你好",
      pinyin: "ni hao",
      note: "Mock translation for tests.",
    } satisfies TranslationResult;
  }

  if (!HACKCLUB_AI_API_KEY) {
    throw new Error("Translation provider is not configured");
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 20000);

  try {
    const response = await fetch(`${HACKCLUB_AI_BASE_URL}/chat/completions`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${HACKCLUB_AI_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: HACKCLUB_AI_MODEL,
        temperature: 0.2,
        stream: false,
        messages: [
          {
            role: "system",
            content:
              "You are a Mandarin translator. Return ONLY valid JSON with keys simplified, traditional, pinyin, note.",
          },
          {
            role: "user",
            content: `Translate this text to Mandarin Chinese and pinyin:\n\n${text}`,
          },
        ],
      }),
      signal: controller.signal,
    });

    const raw = await response.text();
    const providerData = raw ? JSON.parse(raw) : {};

    if (!response.ok) {
      const providerError =
        providerData?.error?.message || providerData?.error || `Provider request failed (${response.status})`;
      throw new Error(providerError);
    }

    const content = providerData?.choices?.[0]?.message?.content;
    if (typeof content !== "string" || !content.trim()) {
      throw new Error("Provider returned an empty translation response");
    }

    let parsed: Partial<TranslationResult> | null = null;
    try {
      parsed = JSON.parse(content) as Partial<TranslationResult>;
    } catch {
      const jsonBlob = extractJsonObject(content);
      if (jsonBlob) {
        parsed = JSON.parse(jsonBlob) as Partial<TranslationResult>;
      }
    }

    if (!parsed) {
      throw new Error("Provider returned invalid translation format");
    }

    const normalized = normalizeTranslation(parsed);
    if (!normalized.simplified || !normalized.traditional || !normalized.pinyin) {
      throw new Error("Provider response missing required translation fields");
    }

    return normalized;
  } finally {
    clearTimeout(timeoutId);
  }
}

function createSessionForUser(userId: number) {
  const token = sessionToken();
  const tokenHash = sha256(token);
  const createdAt = now();
  const expiresAt = createdAt + SESSION_TTL;
  statements.createSession.run(userId, token, tokenHash, createdAt, expiresAt);
  return { token, expiresAt };
}

function findSession(token: string) {
  const hashed = sha256(token);
  const hashedSession = statements.findSessionByTokenHash.get(hashed) as SessionRow | undefined;
  if (hashedSession) {
    return hashedSession;
  }

  const legacySession = statements.findSessionByToken.get(token) as SessionRow | undefined;
  if (!legacySession) {
    return undefined;
  }

  const updatedHash = sha256(token);
  const expiresAt = legacySession.expires_at ?? now() + SESSION_TTL;
  db.prepare("UPDATE sessions SET token_hash = ?, expires_at = ? WHERE id = ?").run(
    updatedHash,
    expiresAt,
    legacySession.id
  );
  return { ...legacySession, token_hash: updatedHash, expires_at: expiresAt };
}

function createApiKeyForUser(userId: number, label?: string) {
  const key = newApiKey();
  const keyHash = sha256(key);
  const createdAt = now();
  statements.createApiKey.run(
    userId,
    key,
    keyHash,
    label?.trim() || null,
    apiKeyPrefix(key),
    apiKeySuffix(key),
    createdAt,
    createdAt
  );

  return {
    apiKey: key,
    prefix: apiKeyPrefix(key),
    last4: apiKeySuffix(key),
    createdAt,
  };
}

function findApiKey(value: string) {
  const hashed = sha256(value);
  const byHash = statements.findApiKeyByHash.get(hashed) as ApiKeyRow | undefined;
  if (byHash) {
    return byHash;
  }

  return statements.findApiKeyByValue.get(value) as ApiKeyRow | undefined;
}

function authMiddleware(c: Context<AppEnv>, next: Next) {
  const header = c.req.header("authorization");
  const token = header?.startsWith("Bearer ") ? header.slice(7).trim() : "";

  if (!token) {
    return c.json({ error: "Missing session token" }, 401);
  }

  const session = findSession(token);
  if (!session || (session.expires_at !== null && session.expires_at <= now())) {
    return c.json({ error: "Invalid or expired session" }, 401);
  }

  const user = statements.findUserById.get(session.user_id) as UserRow | undefined;
  if (!user) {
    return c.json({ error: "Invalid session" }, 401);
  }

  c.set("userId", user.id);
  c.set("userEmail", user.email);
  return next();
}

function apiKeyMiddleware(c: Context<AppEnv>, next: Next) {
  const key = c.req.header("x-api-key")?.trim();
  if (!key) {
    return c.json({ error: "Missing API key" }, 401);
  }

  const keyRow = findApiKey(key);
  if (!keyRow || keyRow.revoked_at !== null) {
    return c.json({ error: "Invalid API key" }, 401);
  }

  c.set("userId", keyRow.user_id);
  const rateScope = `api:${keyRow.key_hash ?? sha256(key)}`;
  const info = rateLimit(rateScope, API_LIMIT, API_WINDOW);
  applyRateLimitHeaders(c, info, API_LIMIT);

  if (!info.allowed) {
    return c.json(
      {
        error: "Rate limit exceeded",
        limit: API_LIMIT,
        resetAt: info.resetAt,
      },
      429
    );
  }

  statements.markApiKeyUsed.run(now(), keyRow.id);
  return next();
}

app.use(cors({ origin: "*" }));
app.use(logger());
app.use(secureHeaders());
app.use("/api/translate", timeout(30000));
app.use("/api/translate", bodyLimit({ maxSize: 12 * 1024 }));

app.get("/api/health", (c) => {
  return c.json({
    ok: true,
    service: "mandarin-api",
    time: now(),
  });
});

app.post("/api/register", async (c) => {
  const limit = rateLimit(`auth:register:${getClientIp(c)}`, AUTH_LIMIT, AUTH_WINDOW);
  applyRateLimitHeaders(c, limit, AUTH_LIMIT);

  if (!limit.allowed) {
    return c.json({ error: "Too many signup attempts", resetAt: limit.resetAt }, 429);
  }

  const body = (await c.req.json()) as JSONValue;
  if (!requireBodyFields(body, ["email", "password"])) {
    return c.json({ error: "Email and password are required" }, 400);
  }

  const email = sanitizeEmail(String(body.email));
  const password = String(body.password);

  if (!email.includes("@") || password.length < 8) {
    return c.json({ error: "Use a valid email and a password with at least 8 characters" }, 400);
  }

  const existing = statements.findUserByEmail.get(email) as UserRow | undefined;
  if (existing) {
    return c.json({ error: "That email is already registered" }, 409);
  }

  statements.createUser.run(email, hashPassword(password), now());
  const created = statements.findUserByEmail.get(email) as UserRow | undefined;
  if (!created) {
    return c.json({ error: "Unable to create user" }, 500);
  }

  const session = createSessionForUser(created.id);
  return c.json({
    token: session.token,
    expiresAt: session.expiresAt,
    user: publicUser(created),
  });
});

app.post("/api/login", async (c) => {
  const limit = rateLimit(`auth:login:${getClientIp(c)}`, AUTH_LIMIT, AUTH_WINDOW);
  applyRateLimitHeaders(c, limit, AUTH_LIMIT);

  if (!limit.allowed) {
    return c.json({ error: "Too many login attempts", resetAt: limit.resetAt }, 429);
  }

  const body = (await c.req.json()) as JSONValue;
  if (!requireBodyFields(body, ["email", "password"])) {
    return c.json({ error: "Email and password are required" }, 400);
  }

  const email = sanitizeEmail(String(body.email));
  const password = String(body.password);

  const user = statements.findUserByEmail.get(email) as UserRow | undefined;
  if (!user || !verifyPassword(password, user.password_hash)) {
    return c.json({ error: "Invalid email or password" }, 401);
  }

  const session = createSessionForUser(user.id);
  return c.json({
    token: session.token,
    expiresAt: session.expiresAt,
    user: publicUser(user),
  });
});

app.post("/api/logout", authMiddleware, (c) => {
  const token = c.req.header("authorization")!.slice(7).trim();
  const tokenHash = sha256(token);
  statements.deleteSessionByTokenHash.run(tokenHash);

  return c.json({ ok: true });
});

app.get("/api/me", authMiddleware, (c) => {
  const userId = c.get("userId");
  const user = statements.findUserById.get(userId) as UserRow | undefined;
  if (!user) {
    return c.json({ error: "User not found" }, 404);
  }

  const activeKeys = statements.listApiKeys.all(userId) as Array<{
    id: number;
    label: string | null;
    key_prefix: string | null;
    key_last4: string | null;
    created_at: number;
    last_used: number | null;
    requests: number | null;
    revoked_at: number | null;
  }>;

  return c.json({
    user: publicUser(user),
    activeKeys: activeKeys.filter((key) => key.revoked_at === null).length,
    totalKeys: activeKeys.length,
  });
});

app.get("/api/keys", authMiddleware, (c) => {
  const userId = c.get("userId");
  const keys = statements.listApiKeys.all(userId);
  return c.json({ keys });
});

app.post("/api/keys", authMiddleware, async (c) => {
  const body = (await c.req.json()) as JSONValue;
  const label = typeof body.label === "string" ? body.label.trim() : "";

  const created = createApiKeyForUser(c.get("userId"), label || undefined);
  return c.json({
    apiKey: created.apiKey,
    label: label || null,
    createdAt: created.createdAt,
  });
});

app.post("/api/generate-key", authMiddleware, async (c) => {
  const body = (await c.req.json().catch(() => ({}))) as JSONValue;
  const label = typeof body.label === "string" ? body.label.trim() : "";

  const created = createApiKeyForUser(c.get("userId"), label || undefined);
  return c.json({
    apiKey: created.apiKey,
    label: label || null,
    createdAt: created.createdAt,
  });
});

app.post("/api/keys/:id/revoke", authMiddleware, (c) => {
  const keyId = Number(c.req.param("id"));
  if (!Number.isInteger(keyId) || keyId <= 0) {
    return c.json({ error: "Invalid key id" }, 400);
  }

  const result = statements.revokeApiKey.run(now(), keyId, c.get("userId"));
  if (result.changes === 0) {
    return c.json({ error: "Key not found" }, 404);
  }

  return c.json({ ok: true });
});

app.get("/api/my-keys", authMiddleware, (c) => {
  return c.json({ keys: statements.listApiKeys.all(c.get("userId")) });
});

app.get("/api/stats", (c) => {
  return c.json({
    users: (statements.countUsers.get() as { count: number }).count,
    activeSessions: (statements.countSessions.get(now()) as { count: number }).count,
    activeKeys: (statements.countKeys.get() as { count: number }).count,
    totalKeyRequests: (statements.countRequests.get() as { total: number }).total,
  });
});

app.post("/api/translate", apiKeyMiddleware, async (c) => {
  const body = (await c.req.json()) as JSONValue;
  const text = typeof body.text === "string" ? body.text.trim() : "";

  if (!text) {
    return c.json({ error: "Text is required" }, 400);
  }

  if (text.length > 500) {
    return c.json({ error: "Text must be 500 characters or less" }, 400);
  }

  try {
    const translated = await translateWithHackClub(text);
    return c.json({
      input: text,
      simplified: translated.simplified,
      traditional: translated.traditional,
      pinyin: translated.pinyin,
      note: translated.note,
      model: HACKCLUB_AI_MODEL,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Translation request failed";
    const status = message.includes("not configured") ? 503 : 502;
    return c.json({ error: message }, status);
  }
});

app.use("/*", serveStatic({ root: "./public" }));

if (import.meta.main) {
  const port = Number(process.env.PORT || 3000);
  Bun.serve({
    port,
    fetch: app.fetch,
  });
}

export { app };
