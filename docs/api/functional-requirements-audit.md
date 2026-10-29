# VAJRA — Functional Requirements Audit (Prompt 0027)

**Working copy:** `/tmp/vajra-durable`  
**Scope:** Evidence-based status of product features.  
**Browser/UI automation:** **Not performed** (source inspection only).  
**Git history:** Unavailable (no `.git` in working copy).

Status legend: **VERIFIED** · **PARTIAL** · **MOCK/PLACEHOLDER** · **BLOCKED** · **NOT IMPLEMENTED**

---

## 1. Authentication & account

| Capability | Status | Evidence | Gaps |
| :--- | :---: | :--- | :--- |
| Register | VERIFIED | `POST /api/auth/register` (`src/server/auth/routes.ts`); Argon2id hash; unit + PG tests | — |
| Login / logout / session | VERIFIED | `POST /api/auth/login`, logout, `GET /api/auth/me`; cookie sessions | Browser E2E not run |
| MFA TOTP enable/verify | VERIFIED | Auth routes + encrypted TOTP secret; PG test enables MFA | — |
| Recovery codes | PARTIAL | Server paths for backup codes in auth routes / notifications copy | Full UI + rotation UX not fully browser-verified |
| Step-up MFA | VERIFIED | `POST /api/auth/step-up`; `requireStepUp`; scope binding; one-time clear | UI modal exists in `App.tsx`; no browser proof |
| Password change | PARTIAL | Route present in auth routes | Limited automated coverage |

**Frontend:** Login/register forms in `src/App.tsx` call real `/api/auth/*`.  
**Tests:** `auth-foundation.test.ts`, `prompt0011d.test.ts`, `postgres-integration.test.ts`.

---

## 2. Device enrollment & inventory

| Capability | Status | Evidence | Gaps |
| :--- | :---: | :--- | :--- |
| List devices | VERIFIED | `GET /api/devices`; UI fetch when session active | Empty inventory shows empty state; sample preview is **opt-in only** (Prompt 0028) |
| Enrollment initiate/submit/confirm | VERIFIED | Device routes + PG enrollment test | Needs real agent for full PoP path |
| Revoke / decommission | PARTIAL | Routes exist (`revoke`, `decommission`) | Limited UI/test depth |
| Heartbeat | VERIFIED (API) | `POST /api/devices/:id/heartbeat` + device auth middleware | Live agent→DB not proven this session |
| Device status | PARTIAL | Inventory + lifecycle fields | Console may show sample devices when none enrolled |

**Mock note:** `MOCK_DEVICES` / `isDemo: true` only when `enrolledDevices` is empty — labeled as sample preview, not live telemetry.

---

## 3. Guard / security events

| Capability | Status | Evidence | Gaps |
| :--- | :---: | :--- | :--- |
| Event ingest (device) | VERIFIED (API) | `POST /api/devices/:id/events` + event engine | Requires signed device agent |
| Event list | PARTIAL | `GET /api/events` | Sparse UI polish |
| Demo seed events | MOCK/PLACEHOLDER | `POST /api/demo/event`, `POST /api/demo/seed` | Explicit demo endpoints — not production evidence |

---

## 4. Locate

| Capability | Status | Evidence | Gaps |
| :--- | :---: | :--- | :--- |
| Request location command | PARTIAL | Allowlisted action on server; agents **do not execute** location | Android: deferred; Windows: unsupported |
| GPS claim | NOT IMPLEMENTED | Agents refuse; docs forbid IP-as-GPS | — |

---

## 5. Recover / remote actions

| Capability | Status | Evidence | Gaps |
| :--- | :---: | :--- | :--- |
| Queue allowlisted command | VERIFIED (API) | `POST /api/devices/:id/actions` / commands; step-up for sensitive | Execution ≠ queue |
| REQUEST_DEVICE_STATUS | PARTIAL | Windows + Android matrices support | Live receipt not proven this session |
| RING_DEVICE | PARTIAL | Android only | Windows returns unsupported |
| Lost mode / recovery message | PARTIAL | Server allowlist + UI controls | Agents do not implement lost mode; server may update lifecycle without device proof |
| Shell / RCE | NOT IMPLEMENTED | Rejected by design | Correct |

---

## 6. Alerts & activity

| Capability | Status | Evidence | Gaps |
| :--- | :---: | :--- | :--- |
| Notifications list/ack | VERIFIED (API) | `/api/notifications*` | — |
| Activity timeline | VERIFIED (API) | `/api/activity` + audit translation in UI | — |

---

## 7. ThreatCheck

| Capability | Status | Evidence | Gaps |
| :--- | :---: | :--- | :--- |
| URL inspect | VERIFIED | `POST /api/threatcheck/inspect`; `urlSafety.ts` | External intel may be heuristic |
| History + pagination | VERIFIED | `GET /api/threatcheck/history`; UI + tests | — |
| Export | VERIFIED | `/api/reports/export` JSON/CSV | Formula-injection mitigations in tests |

---

## 8. Analytics

| Capability | Status | Evidence | Gaps |
| :--- | :---: | :--- | :--- |
| Summary API | VERIFIED | `GET /api/analytics/summary`; `dataSource: PERSISTED` | Empty datasets honest |
| Charts | PARTIAL | UI bound to API | Visual validation not run |

---

## 9. Settings / privacy / account lifecycle

| Capability | Status | Evidence | Gaps |
| :--- | :---: | :--- | :--- |
| Settings UI | PARTIAL | Sections in `App.tsx` | Account delete may be incomplete |
| Privacy disclosure (Android) | PARTIAL | Android Privacy activity | — |

---

## 10–11. Windows / Android agents

| Platform | Supported commands | Partial / unsupported | Status |
| :--- | :--- | :--- | :--- |
| Windows | `REQUEST_DEVICE_STATUS` | Location, ring, lost mode, shell — unsupported | Build verified prior; **not rerun this session** |
| Android | `REQUEST_DEVICE_STATUS`, `RING_DEVICE` | Location deferred; lost mode unsupported | Unit tests + APK verified prior; **not rerun this session** |

Signing: Plane-2 DER ECDSA P-256; enrollment PoP; protocol matrix in `docs/architecture/device-protocol-matrix.md`.

---

## 12. Database

| Capability | Status | Evidence |
| :--- | :---: | :--- |
| Migrations 0003–0007 | VERIFIED | Applied successfully in prior PG sessions |
| Audit immutability trigger | VERIFIED | PG integration test (when DB up) |
| Analytics views / indexes | VERIFIED | SQL evidence + migrations |
| This session PG suite | BLOCKED | PostgreSQL not reachable at audit time |

---

## UI honesty findings (source)

1. **Sample devices:** When no enrolled devices, UI shows `MOCK_DEVICES` with `isDemo: true` and explicit preview copy — acceptable if never presented as live agent data.
2. **Remote actions:** Must remain receipt-gated; queued ≠ executed.
3. **docs/api/endpoints.md** still contains some outdated `PLANNED` labels alongside newer IMPLEMENTED sections — documentation drift (Medium).
