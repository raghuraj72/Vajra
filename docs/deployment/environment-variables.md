# VAJRA — Environment Variables Reference

**Status:** Prompt 0013  
**Source of truth for names:** `packages/config/src/index.ts`, `server.ts`, `src/server/auth/*`, Prisma

Secrets must never be logged or committed. Use Azure App Settings / Key Vault references in production.

| Variable | Required (prod) | Purpose |
| :--- | :---: | :--- |
| `NODE_ENV` | Yes | `production` / `development` / `test` |
| `APP_ENV` | Yes | Aligns with `NODE_ENV` for production gates |
| `PORT` | Yes (platform) | Listen port; App Service injects automatically |
| `DATABASE_URL` | Yes | PostgreSQL URL; production rejects placeholders |
| `SESSION_SECRET` | Yes | ≥32 char non-placeholder; session integrity material |
| `TOTP_ENCRYPTION_KEY` | Yes | ≥32 char; AES-GCM for TOTP secrets; distinct from session |
| `TRUST_PROXY` | Recommended | `true` behind Azure TLS termination |
| `APP_PUBLIC_ORIGIN` | Recommended | Canonical https origin |
| `APP_URL` | Optional | Alternate name accepted for public origin |
| `SESSION_TTL_SECONDS` | Optional | Idle session policy (60–86400) |
| `REQUIRE_MFA` | Optional | Policy flag (default true) |
| `VAJRA_SEED_*` | No (dev only) | Seed script only |
| `VITE_LOGIN_BG_VIDEO_URL` | Optional | Build-time login video URL |
| `GEMINI_API_KEY` | Optional | Only if AI features enabled |

## Production validation behavior

`assertProductionConfigOrThrow()` / `validateRuntimeConfig()` reject:

- Missing or placeholder `DATABASE_URL`
- Short or placeholder secrets
- Identical `SESSION_SECRET` and `TOTP_ENCRYPTION_KEY`

## Local development

1. `cp .env.example .env`
2. Optionally set a real local `DATABASE_URL`; otherwise the server uses in-memory identity **only when not in production**.

## Disposable test-only configuration (Prompt 0036)

1. See `.env.test.example` for placeholder-only test environment variables (`NODE_ENV="test"`, `APP_ENV="test"`, `VAJRA_PG_INTEGRATION="1"`).
2. Integration tests (`npm run test:pg`) require a non-placeholder loopback PostgreSQL URL whose database name contains `test` (e.g. `vajra_test`) and refuse to run when `NODE_ENV=production` or `APP_ENV=production`.
3. Keep `VAJRA_ENABLE_DEMO_ENDPOINTS="false"` during verification and keep test users, devices, and nonces isolated per test run.
