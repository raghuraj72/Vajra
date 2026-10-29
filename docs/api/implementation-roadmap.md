# VAJRA — Implementation Roadmap (Prompt 0027)

Ordered by risk and user-journey impact. Each item lists acceptance criteria and proof tests.

---

## Phase A — Security & data integrity (do first)

| # | Task | Acceptance | Proof |
| :---: | :--- | :--- | :--- |
| A1 | Keep receipt-gated remote actions | UI never shows COMPLETED without device result / honest FAILED unsupported | Unit tests for command transitions; UI copy review |
| A2 | Production-disable or hard-gate `/api/demo/*` | Demo routes 404 or require explicit non-prod flag | Integration test |
| A3 | Align `docs/api/endpoints.md` with real routes | No stale PLANNED for live endpoints | Doc diff + grep of routers |
| A4 | Re-run PG suite on every release candidate | 7/7 (or current count) green on disposable DB | `VAJRA_PG_INTEGRATION=1 npm run test:pg` |

---

## Phase B — Core journeys that must work

| # | Task | Acceptance | Proof |
| :---: | :--- | :--- | :--- |
| B1 | Empty-device inventory UX | Only sample preview when zero devices; clear CTA to enroll | Manual + optional browser test |
| B2 | Enrollment console flow | Initiate → display token once → confirm → device TRUSTED | PG + API tests; optional UI |
| B3 | Step-up modal path | 403 STEP_UP_REQUIRED → modal → retry once → success/fail honest | Existing 0011 tests + UI check |
| B4 | ThreatCheck inspect + history | Persist and paginate; no “100% safe” | Existing tests |

---

## Phase C — Backend / device integration

| # | Task | Acceptance | Proof |
| :---: | :--- | :--- | :--- |
| C1 | Windows agent live against local API+PG | Enroll, heartbeat, status command, revoke | Manual on Windows host |
| C2 | Android agent live | Enroll, heartbeat, RING with visible notification | Emulator/device |
| C3 | Unsupported commands | Agent returns FAILED + safeMessage; no fake COMPLETED | Agent unit + server |

---

## Phase D — Functional completeness

| # | Task | Acceptance | Proof |
| :---: | :--- | :--- | :--- |
| D1 | Recovery codes full UX | Generate, download once, consume, regenerate with password | API+UI tests |
| D2 | Account password change / MFA disable | Password confirm required | API tests |
| D3 | Lost-mode honesty | No agent success claim until platform support exists | Capability matrix enforced |

---

## Phase E — Accessibility, responsiveness, UX refinement

| # | Task | Acceptance | Proof |
| :---: | :--- | :--- | :--- |
| E1 | Keyboard paths for auth and MFA modal | Focus trap, labels | Manual a11y checklist |
| E2 | Reduced motion | Honors `prefers-reduced-motion` | Existing UI tests partially |
| E3 | Mobile nav | Usable at 375px width | Manual |

---

## Phase F — Regression & release readiness

| # | Task | Acceptance | Proof |
| :---: | :--- | :--- | :--- |
| F1 | Full local matrix | lint, unit, build, audit, PG, Windows build, Android unit/APK | CI or scripted |
| F2 | Azure deploy only after approval | HTTPS health/ready; no secrets in git | Controlled deploy prompt |

---

## Completed in Prompt 0028

- Inventory no longer treats MOCK_DEVICES as real devices; demo events disabled in production.

## Single recommended next implementation task

**B2 + C1 coordination:** Prove one real Windows (or Android) enrollment against local Express + PostgreSQL, with heartbeat and one supported command receipt, and ensure the web console shows only server-persisted device state (no demo confusion).

This closes the largest honesty gap between “API exists” and “product journey works.”
