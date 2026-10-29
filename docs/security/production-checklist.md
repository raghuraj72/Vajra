# VAJRA — Production Security Checklist

**Status:** Prompt 0013 operational checklist  
Use before exposing a deployment beyond a private test slot.

## Configuration

- [ ] `NODE_ENV=production` and `APP_ENV=production`
- [ ] Non-placeholder `DATABASE_URL` with TLS (`sslmode=require`)
- [ ] Distinct `SESSION_SECRET` and `TOTP_ENCRYPTION_KEY` (≥32 chars each)
- [ ] `TRUST_PROXY=true` on Azure App Service
- [ ] HTTPS-only site; HSTS emitted by the app in production
- [ ] App settings / Key Vault — no secrets in Git

## Application controls (implemented in code)

- [x] CSRF + Origin checks on mutating browser routes
- [x] Session cookies HttpOnly; Secure under HTTPS
- [x] MFA / step-up for sensitive device actions
- [x] Device signature + nonce replay protection
- [x] Command receipt integrity and terminal-state immutability
- [x] API `Cache-Control: no-store`
- [x] CSP baseline (`default-src 'self'`; Cloudinary media exception for login video)
- [x] Request body limit 16kb JSON
- [x] Production fails closed without PostgreSQL
- [x] Liveness `/api/health` and readiness `/api/ready`

## Database

- [ ] Least-privilege DB role
- [ ] Firewall / private network restricts access to app only
- [ ] `prisma migrate deploy` applied through 0007
- [ ] Backup / PITR enabled on Flexible Server

## Operations

- [ ] Health probes configured (liveness + readiness)
- [ ] Log stream reviewed for absence of secrets
- [ ] Test account created with dummy data only
- [ ] Rollback path documented

## CSP notes

- `style-src 'self' 'unsafe-inline'` is required for some Vite/Tailwind runtime styles; tighten further only after verifying the production CSS pipeline.
- `media-src` / `img-src` allow `https://res.cloudinary.com` for the optional login background video.

## Planned (not production blockers for MVP API)

- Windows / Android agents
- Azure Blob evidence storage
