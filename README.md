# scan-secrets

Find potential secrets in text before you paste it into an external service (including AI tools). Scanning runs entirely in the browser — text, files, and findings are never uploaded.

**Version:** `0.1.3`  
**License:** [MIT](LICENSE)
**Live:** https://secretscanner.dmosk.net

## Stack

| Layer | Choice |
|-------|--------|
| UI / logic | Vite + TypeScript (vanilla), no runtime dependencies |
| API | None — user content never leaves the browser |

## Features

- Paste text or open a text file (up to 5 MB, read with `File.text()`)
- Heuristic findings list: category, rule, snippet, line context, position
- Checkboxes per finding (all selected by default), select/deselect all
- Replace selected findings with `[REDACTED]` in the editor, then rescan
- Copy cleaned text
- PWA: installable and usable offline after the first visit
- SEO body below the tool plus JSON-LD `WebApplication` and `FAQPage`

Detection is a hint, not a guarantee. For repositories use a CI scanner such as gitleaks.

## What it looks for

| Category | Examples |
|----------|----------|
| Private keys | `BEGIN … PRIVATE KEY` blocks |
| Tokens | GitHub, GitLab, Slack, OpenAI, AWS access key patterns |
| JWT | three base64url segments starting with `eyJ` |
| Credential URIs | password part of `scheme://user:password@host` |
| Assignments | `password` / `secret` / `api_key` / `token`-like keys |
| High entropy | long mixed alphanumeric strings (pure hex hashes skipped) |

Implementation: `src/scan.ts`, `src/redact.ts`.

## Languages and URLs

- Locale paths: `/ru/`, `/en/`, `/zh/`, `/es/`, `/hi/`, `/ar/`, `/bn/`, `/pt/`, `/fr/`, `/de/`, `/ja/`, `/id/`, `/pa/`, `/jv/`, `/te/`, `/tr/`, `/ko/`, `/mr/`, `/vi/`, `/ta/`, `/it/`, `/fa/`, `/tlh/`
- Language switcher uses local Twemoji flag PNGs; `ar` / `fa` use `dir="rtl"`
- Self-canonical URLs and full hreflang; `x-default` → `/en/`
- Build writes `dist/{lang}/`

## Local development

```bash
npm install
npm run dev
```
