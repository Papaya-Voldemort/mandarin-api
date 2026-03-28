# mandarin-api

A TS Hono API that takes english as an input and translates it into all forms of Mandarin Chinese, this includes Traditional (Taiwan), Simplified (Main Land), and PinYin (English Speaker Readable). 

## Devlogs

### #1:
Hello World! This is Mandarin API's first devlog, I kind of forgot how to start these lol!
This is going to be a TS Hono API that takes english as an input and translates it into all forms of Mandarin Chinese, this includes Traditional (Taiwan), Simplified (Main Land), and PinYin (English Speaker Readable). 

I am building this tool because I love Taiwan and am working on learning Chinese so I can live there someday :)

Technical Specs:
- Bun (Faster than Node)
- Hono (Easy and fast works with Bun)
- Translation (OpenRouter model for now eventually custom solution)

This first version is a MVP to get things working before I implement a custom translation solution!

## Requirements

- Bun v1.3.11 or newer
- `hono` (installed automatically via `bun install`)
- `dotenv` (installed automatically via `bun install`)
- OpenRouter API key (set in `API_KEY` environment variable)

## Environment

Create a `.env` file at project root:

```ini
API_KEY=your_openrouter_api_key
```

> Note: Bun automatically loads `.env` files.

## Setup

To install dependencies:

```bash
bun install
```

To run (development):

```bash
bun run dev
```

To run directly:

```bash
bun run index.ts
```

This project was created using `bun init` in bun v1.3.11. [Bun](https://bun.com) is a fast all-in-one JavaScript runtime.
