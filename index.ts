import { Hono } from 'hono'

type TranslateRequest = {
  text: string
}

type OpenRouterChoice = {
  message?: {
    content?: string
  }
}

type OpenRouterResponse = {
  choices?: OpenRouterChoice[]
}

const app = new Hono()
const API_KEY = process.env.API_KEY

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
  })

  const data = (await res.json()) as OpenRouterResponse
  const rawText = data.choices?.[0]?.message?.content ?? '{}'

  try {
    return JSON.parse(rawText) as Record<string, string>
  } catch {
    return { error: rawText }
  }
}

app.post('/translate', async (c) => {
  const body = (await c.req.json()) as TranslateRequest
  const parsed = await callOpenRouter(body)
  return c.json(parsed)
})

export default app