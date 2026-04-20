import { expect, test } from "bun:test";
import crypto from "crypto";

const sqlitePath = `./data/test-${crypto.randomUUID()}.db`;
process.env.SQLITE_PATH = sqlitePath;
process.env.TRANSLATE_MOCK = "1";

const { app } = await import("./index.ts");

async function json(path: string, body?: unknown, headers: Record<string, string> = {}) {
  return app.fetch(
    new Request(`http://localhost${path}`, {
      method: body ? "POST" : "GET",
      headers: body ? { "Content-Type": "application/json", ...headers } : headers,
      body: body ? JSON.stringify(body) : undefined,
    })
  );
}

test("signup, create key, and translate", async () => {
  const email = `user-${crypto.randomUUID()}@example.com`;
  const password = "correct horse battery staple";

  const register = await json("/api/register", { email, password });
  expect(register.status).toBe(200);
  const registerData = (await register.json()) as { token: string };

  const me = await json("/api/me", undefined, {
    Authorization: `Bearer ${registerData.token}`,
  });
  expect(me.status).toBe(200);

  const keyResponse = await json(
    "/api/keys",
    { label: "test key" },
    {
      Authorization: `Bearer ${registerData.token}`,
    }
  );
  expect(keyResponse.status).toBe(200);
  const keyData = (await keyResponse.json()) as { apiKey: string };

  const translate = await json(
    "/api/translate",
    { text: "Hello there" },
    {
      "x-api-key": keyData.apiKey,
    }
  );
  expect(translate.status).toBe(200);
  const translated = (await translate.json()) as { simplified: string; traditional: string; pinyin: string };
  expect(translated.simplified.length).toBeGreaterThan(0);
  expect(translated.traditional.length).toBeGreaterThan(0);
  expect(translated.pinyin.length).toBeGreaterThan(0);
});

test("rate limits login attempts", async () => {
  const email = `limit-${crypto.randomUUID()}@example.com`;
  const password = "correct horse battery staple";
  await json("/api/register", { email, password });

  for (let attempt = 0; attempt < 8; attempt += 1) {
    const response = await json("/api/login", { email, password: "wrong-password" });
    expect(response.status).toBe(401);
  }

  const blocked = await json("/api/login", { email, password: "wrong-password" });
  expect(blocked.status).toBe(429);
});
