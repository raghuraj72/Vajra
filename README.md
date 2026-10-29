# VAJRA — Intelligent Digital Security

**VAJRA** (वज्र — representing strength, protection, and resilience) is a personal cross-device cybersecurity and device-recovery platform designed to help users monitor and protect their own trusted **Windows PCs/laptops** and **Android phones** through a secure web console.

> **Ethical & Legal Scope:**  
> **VAJRA is designed to protect devices owned or explicitly authorized by the user.**  
> VAJRA is a legitimate personal-device security product. It is strictly **not** stealth spyware, offensive malware, or covert surveillance software. It operates exclusively through documented OS APIs, explicit user permissions, and hardware-backed cryptographic identity.

---

## 1. Core Responsibilities

1. **Protect (`VAJRA Guard`)** — Hardware-backed cryptographic device identity (`Device ID + Public Key + Proof`) and least-privilege posture monitoring.
2. **Detect (`VAJRA Guard`)** — Legitimate Windows and Android security event detection without collecting passwords, keystrokes, or private files.
3. **Alert (`VAJRA Alert`)** — Deduplicated, prioritized notifications across `SECURITY`, `DEVICE`, `LOCATION`, `TAMPER`, `THREAT`, `RECOVERY`, and `SYSTEM` categories (`INFO` to `CRITICAL`).
4. **Locate (`VAJRA Locate`)** — Permission-aware device location with explicit `LocationSource`, `LocationAccuracy`, `Timestamp`, and `PermissionState` (never misrepresenting `IP_APPROXIMATE` as GPS).
5. **Recover (`VAJRA Recover`)** — Step-up authorized remote phone ringing (`RING_PHONE`), Lost Mode (`ENABLE_LOST_MODE` / `DISABLE_LOST_MODE`), and a privacy-preserving Android Custom Recovery Screen (`DISPLAY_RECOVERY_MESSAGE`).
6. **Analyze Threats (`ThreatCheck` & `Risk Engine`)** — Safe URL/website analysis (`ThreatIntelProvider` abstraction with query secret redaction and SSRF protection) and explainable `0–100` deterministic risk scoring.

---

## 2. Active Technology Stack

- **Active Web Console:** `React 19 + TypeScript + Tailwind CSS v4 + Vite`
- **Active Backend Foundation:** `Node.js + Express + TypeScript` (`server.ts` & `src/server/app.ts` listening on port `3000`)
- **Shared Monorepo Packages:** `@vajra/shared-types`, `@vajra/security`, `@vajra/config`
- **Planned Database (Stage 0003):** `PostgreSQL + Prisma ORM` (15 specified entities)
- **Planned Endpoint Agents (Stages 0005–0006):** `C# / .NET 8+` Windows Service & `Native Kotlin` Android App
- **Database:** `PostgreSQL + Prisma` (migrations `0003`–`0007`; production requires a live DB)
- **Deployment target (config ready):** Azure App Service + Azure Database for PostgreSQL — see `docs/deployment/azure-app-service.md`

### Local development

```bash
cp .env.example .env
# Optional: set DATABASE_URL, SESSION_SECRET, TOTP_ENCRYPTION_KEY
npm install --legacy-peer-deps
npx prisma generate
npm run dev          # http://0.0.0.0:3000
```

### Production-oriented commands (configuration only; does not deploy for you)

```bash
npm run build
export NODE_ENV=production APP_ENV=production
export DATABASE_URL="postgresql://...&sslmode=require"
export SESSION_SECRET="$(openssl rand -hex 32)"
export TOTP_ENCRYPTION_KEY="$(openssl rand -hex 32)"
export TRUST_PROXY=true
npx prisma migrate deploy
npm run start:prod
```

Health: `GET /api/health` (liveness) · `GET /api/ready` (PostgreSQL readiness).  
**This repository does not claim that Azure resources have been provisioned or that a production deploy has been executed.**

---

## 3. Current Implementation Status (`IMPLEMENTED` / `MOCKED` / `PLANNED`)

To maintain complete transparency, every capability in this repository is explicitly categorized:

| Capability / Deliverable | Status | Stage & Reference |
| :--- | :--- | :--- |
| **Monorepo Foundation, Config & Shared Types** | **`IMPLEMENTED`** | Stage 0001 — `packages/shared-types`, `packages/security`, `packages/config` |
| **Backend Health Endpoint (`GET /api/health`)** | **`IMPLEMENTED`** | Stage 0001 — `src/server/app.ts` (`{"status":"ok","service":"vajra-api"}`) |
| **Web Console Shell & Navigation Layout** | **`IMPLEMENTED`** | Stage 0001 — `src/App.tsx` (Dark cybersecurity UI with Vajra motif) |
| **Complete Product, Security & API Specification Suite** | **`IMPLEMENTED` (Docs)** | Stage 0002 — 19 specification documents indexed in Section 4 below |
| **Initial Dashboard Telemetry (`ASUS TUF F16` & `Android Phone`)** | **`MOCKED`** | Stage 0001 — `src/data/mockFoundationData.ts` (Explicitly labeled mock preview) |
| **PostgreSQL + Prisma Schema & Migration (`0003_identity_foundation`)** | **`IMPLEMENTED`** | Stage 0003 — `prisma/schema.prisma` (`User`, `UserCredential`, `PasskeyCredential`, `Device`, `DeviceCredential`, `DeviceSession`, `AuditLog`) |
| **Plane 1 Auth (Argon2id, AES-256-GCM TOTP MFA, Recovery Codes, CSRF, Sessions & Audit Chain)** | **`IMPLEMENTED`** | Stage 0003 — `packages/security/src/*`, `src/server/auth/*`, `docs/security/csrf.md` |
| **WebAuthn Passkey Runtime Ceremonies** | **`PARTIALLY IMPLEMENTED`** | Stage 0003 — `PasskeyCredential` schema prepared; runtime assertion deferred to avoid fake iframe simulation |
| **Plane 2 Device Identity & Enrollment Ceremony** | **`PLANNED`** | Stage 0004 — `docs/security/device-enrollment.md` & `docs/architecture/device-lifecycle.md` |
| **Windows Security Agent (`C# / .NET`)** | **`PLANNED`** | Stage 0005 — `docs/platform/windows.md` |
| **Android Security Application (`Kotlin`)** | **`PLANNED`** | Stage 0006 — `docs/platform/android.md` |
| **Security Event Ingestion, Timeline & Alerting** | **`PLANNED`** | Stage 0007 — `docs/product/event-taxonomy.md` & `docs/product/security-timeline.md` |
| **Plane 3 Remote Commands & Lost-Device Recovery** | **`PLANNED`** | Stage 0008 — `docs/security/remote-command-security.md` & `docs/product/PRD.md` |
| **ThreatCheck URL Analysis Engine** | **`PLANNED`** | Stage 0009 — `docs/product/threatcheck.md` & `docs/security/authorized-testing.md` |
| **Explainable Risk Engine (`0–100`)** | **`PLANNED`** | Stage 0010 — `docs/product/risk-engine.md` |
| **Adversarial Hardening & Production Readiness** | **`PLANNED`** | Stages 0011–0012 — `docs/security/testing-strategy.md` & `docs/product/roadmap.md` |

---

## 4. Documentation Index

```text
Documentation (docs/)
├── Product (docs/product/)
│   ├── PRD.md                        # Master Product Requirements Document (Modules 1–6)
│   ├── event-taxonomy.md             # Canonical SecurityEvent envelope & extensible categories
│   ├── threatcheck.md                # Safe URL analysis, ThreatIntelProvider & secret redaction
│   ├── risk-engine.md                # Explainable 0–100 deterministic risk scoring model
│   ├── security-timeline.md          # Chronological feed, filtering, coalescing & cursor pagination
│   ├── mvp.md                        # Minimum Viable Product scope (Inside vs. Outside MVP)
│   ├── roadmap.md                    # 12-Stage development & security roadmap (0001–0012)
│   └── acceptance-criteria.md        # Measurable verification conditions for all core features
│
├── Architecture (docs/architecture/)
│   ├── overview.md                   # System topology & component responsibilities
│   ├── database.md                   # 15 planned PostgreSQL/Prisma entities & retention rules
│   ├── device-lifecycle.md           # State machine (UNREGISTERED -> TRUSTED -> ACTIVE -> REVOKED)
│   ├── failure-model.md              # 10 offline, timeout, crash, expiry & compromise scenarios
│   └── observability.md              # Structured logging, sanitizeLogMetadata, metrics & AuditLog
│
├── Security (docs/security/)
│   ├── security-principles.md        # Core cryptographic charter & Three-Plane Trust summary
│   ├── threat-model.md               # Threats 1–8 impact & mitigation matrix
│   ├── authentication.md             # Passkeys/WebAuthn, Argon2id+MFA, session rotation & lockout
│   ├── csrf.md                       # Three-layer CSRF defense (SameSite, Origin, X-CSRF-Token)
│   ├── authorization-matrix.md       # Actor permission matrix across User, Device & Backend planes
│   ├── device-enrollment.md          # Pairing tokens, Proof-of-Possession & revocation ceremony
│   ├── remote-command-security.md    # Command allowlist, nonces, signatures & replay defense
│   ├── authorized-testing.md         # Standard passive URL check vs. Authorized Security Audit
│   ├── privacy-model.md              # Data minimization, AES-256-GCM encryption & user controls
│   └── testing-strategy.md           # Unit, integration, negative security, platform & URL test suites
│
├── API (docs/api/)
│   ├── README.md                     # API route group index & implemented /api/health overview
│   └── endpoints.md                  # Full REST endpoint contracts, auth, rate limits & audit rules
│
└── Platform (docs/platform/)
    ├── android.md                    # Android 10–15 permissions, Keystore, Doze, Ring & Recovery Screen
    └── windows.md                    # Windows 10/11 SCM service, CNG/TPM, Event Logs & Defender coexistence
```

---

## 5. Non-Negotiable Security Boundaries

VAJRA **never** implements (`packages/security/src/index.ts`):
- Stealth spyware, keylogging, password collection, or credential theft
- Hidden microphone, webcam, or covert screen recording
- Bypassing Android permissions, Windows security, or Windows Defender/antivirus
- Rootkits, evasive persistence, or privilege escalation
- Arbitrary remote shell execution (`EXECUTE_SHELL`) or arbitrary remote code execution (`DOWNLOAD_AND_EXECUTE`)
- Unauthorized intrusive vulnerability scanning against third-party websites

---

## 6. Development & Verification Commands

```bash
# Install dependencies
npm install

# Run TypeScript strict lint / typecheck
npm run lint
npm run typecheck

# Run automated foundation test suite
npm test

# Build production web bundle
npm run build

# Start development server (Express API + React/Vite Web Console on port 3000)
npm run dev
```
