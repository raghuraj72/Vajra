# VAJRA — Non-Functional Requirements Audit (Prompt 0027)

**Working copy:** `/tmp/vajra-durable`  
**Browser a11y/visual pass:** Not performed.

Severity: Critical · High · Medium · Low

---

## Security controls

| Area | Assessment | Severity if gap | Evidence / note |
| :--- | :--- | :---: | :--- |
| Cross-user isolation | Strong (API + PG tests) | — | Enrollment/analytics deny other users |
| Session cookies | Secure design in production | Medium | Depends on `TRUST_PROXY` + HTTPS in deploy |
| CSRF | Implemented | — | `x-csrf-token` + middleware |
| Rate limits | Partial | Medium | Confirm coverage on auth endpoints under load |
| MFA / step-up | Implemented | — | Scope-bound; one-time consumption |
| Password hashing | Argon2id | — | `packages/security/src/password.ts` |
| Recovery codes | Present | Medium | Ensure hashed at rest (verify store format) |
| Device signatures | Strong | — | Canonical body, DER ECDSA, ±120s, nonce 409 |
| Route/device binding | Implemented | — | `assertDeviceRouteBinding` |
| Command terminal immutability | Implemented | — | Legal transitions + first-result wins |
| SQL injection | Mitigated via Prisma | — | — |
| XSS / CSP | Headers set on API app | Medium | Full CSP for SPA needs deploy verification |
| CSV formula injection | Tested | — | Analytics export tests |
| Audit append-only | DB trigger | — | `trg_prevent_audit_log_mutation` |
| Secrets in repo | None observed | — | Override deepmerge only |
| npm audit | Clean (0) with deepmerge override | Low | Revisit when Prisma pins deepmerge ≥8 |

### Findings

1. **High — Live agent E2E unproven:** Command execution claims require authentic receipts; console must not imply success on queue alone.  
2. **Medium — API docs drift:** Mixed PLANNED/IMPLEMENTED labels in `docs/api/endpoints.md`.  
3. **Medium — Demo endpoints:** `/api/demo/*` must remain non-default in production builds.  
4. **Low — Accessibility:** No automated a11y suite; keyboard/focus/ARIA not systematically tested.  
5. **Low — Responsive:** Tailwind layouts exist; no formal breakpoint QA.

---

## Reliability & API semantics

| Topic | Status |
| :--- | :--- |
| Health / ready | Implemented (`/api/health`, `/api/ready`) |
| Production fail-closed DB | Implemented (`server.ts`) |
| Idempotent command results | Implemented |
| Graceful shutdown | Partial (process handlers — confirm signal handling) |
| Timeouts/retries (agents) | Agent-side workers; not fully integration-tested |

---

## Privacy

| Topic | Status |
| :--- | :--- |
| Data minimization in events | Event engine redaction |
| Location consent | Location not implemented on agents |
| Android permissions | Explicit; RING uses user-visible notification |
| Retention policy | Documented conceptually; automated purge not verified |

---

## Performance

| Topic | Status |
| :--- | :--- |
| Analytics indexes | Migration 0007 |
| Polling | Device agents poll; console fetches on navigation | Avoid aggressive intervals in UI |
| Large lists | ThreatCheck pagination exists |

---

## Operational readiness

| Topic | Status |
| :--- | :--- |
| Azure deploy | BLOCKED (no CLI/auth/approval) |
| Observability | Logs/health only; no APM assumed |
| Local PG verification | Works when PostgreSQL installed |
