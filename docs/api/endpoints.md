# VAJRA — Detailed REST API Endpoint Specification

**Base URL Prefix:** `/api`  
**Document Status:** Complete API Contract Specification (`IMPLEMENTED` in Prompts 0001–0008: `GET /api/health`, `/api/auth/*`, `GET /api/audit`, `GET /api/devices`, `GET /api/devices/:id`, `POST /api/devices/enrollment/initiate`, `POST /api/devices/enrollment/submit`, `POST /api/devices/:id/enrollment/confirm`, `POST /api/devices/:id/revoke`, `POST /api/devices/:id/compromised`, `POST /api/devices/:id/decommission`, `POST /api/devices/auth/verify`, `POST /api/devices/credentials/rotate`, `GET /api/notifications`, `POST /api/notifications/:id/read`, `POST /api/notifications/read-all`, `POST /api/notifications/:id/acknowledge`, `POST /api/notifications/:id/dismiss`, `GET /api/activity`, `POST /api/events/ingest`, `POST /api/devices/:id/events`, `GET /api/events`, `GET /api/security/risk`, `POST /api/threatcheck/inspect`, `GET /api/devices/:id/commands`, `POST /api/devices/:id/commands`, `GET /api/devices/:id/commands/pending`, `POST /api/devices/:id/commands/:commandId/ack`, `POST /api/devices/:id/commands/:commandId/result`, `POST /api/devices/:id/commands/:commandId/cancel`, `POST /api/devices/:id/heartbeat`, `POST /api/demo/event`, `POST /api/demo/seed`)  
**Related Documents:** `docs/security/authentication.md`, `docs/security/csrf.md`, `docs/security/authorization-matrix.md`, `docs/security/remote-command-security.md`, `docs/security/device-enrollment.md`

---

## Global API Conventions

- **Content-Type:** `application/json; charset=utf-8` (request payloads capped at `16 KB` by default).
- **Standard Error Envelope:**
  ```json
  {
    "error": {
      "code": "STEP_UP_AUTH_REQUIRED",
      "message": "This remote command requires fresh Passkey or MFA step-up verification.",
      "correlationId": "req_01J9ZA88B0C1D2E3F4G5H6J7K8"
    }
  }
  ```
- **Authentication Planes:**
  - `Plane 1 (User Session)`: `HttpOnly`, `Secure`, `SameSite=Strict` session cookie (`__Host-vajra_session`) + `X-CSRF-Token` header on state-changing requests.
  - `Plane 2 (Device Signature)`: `X-Vajra-Device-Id`, `X-Vajra-Timestamp`, `X-Vajra-Nonce`, and `X-Vajra-Signature` (Ed25519 / ECDSA P-256 signature over request body + timestamp + nonce).
  - `Plane 3 (Step-Up Command Auth)`: Requires active Plane 1 session with `stepUpVerifiedUntil > now()` (within 5 minutes of Passkey/MFA challenge).

---

## 0. Health Check (`IMPLEMENTED`)

### `GET /api/health`
- **Purpose:** Verify API liveness without exposing environment variables, database credentials, or internal paths.
- **Authentication:** None (Public).
- **Authorization:** Public read-only liveness check.
- **Request:** No parameters or body.
- **Response (`200 OK`):**
  ```json
  {
    "status": "ok",
    "service": "vajra-api"
  }
  ```
- **Errors:** `503 Service Unavailable` if server process is shutting down.
- **Rate Limits:** `120 requests / minute / IP`.
- **Audit Requirements:** None (high-frequency health probe).

---

## 0. Health & readiness

### `GET /api/health`
- **Auth:** None
- **Purpose:** Liveness — process is running.
- **Body:** `{"status":"ok","service":"vajra-api"}`

### `GET /api/ready`
- **Auth:** None
- **Purpose:** Readiness — identity store probe (bounded timeout).
- **200:** `status: "ready"` with `checks.identityStore.ok: true`
- **503:** `status: "not_ready"` without connection strings or stack traces

## 1. Authentication Group (`/api/auth` — `IMPLEMENTED`)

### 1.1 `POST /api/auth/login`
- **Purpose:** Authenticate the account owner using WebAuthn Passkey assertion or Argon2id password + mandatory MFA challenge.
- **Authentication:** Public endpoint initiating Plane 1 session.
- **Authorization:** Account must be in `ACTIVE` state.
- **Request Body:**
  ```json
  {
    "email": "owner@example.com",
    "method": "PASSKEY_ASSERTION",
    "passkeyAssertion": { "id": "...", "response": {} },
    "mfaCode": "123456"
  }
  ```
- **Response (`200 OK`):** Sets `__Host-vajra_session` cookie and returns `{ "user": { "id": "...", "email": "...", "displayName": "..." }, "sessionExpiresAt": "..." }`.
- **Errors:**
  - `400 Bad Request` (`INVALID_INPUT`)
  - `401 Unauthorized` (`INVALID_CREDENTIALS` or `MFA_REQUIRED`)
  - `423 Locked` (`ACCOUNT_TEMP_LOCKED`)
  - `429 Too Many Requests` (`RATE_LIMIT_EXCEEDED`)
- **Rate Limits:** `5 attempts / 15 minutes / IP + email`.
- **Audit Requirements:** Writes `USER_LOGIN_SUCCESS` or `USER_LOGIN_FAILURE` to `AuditLog` and emits `LOGIN_SUCCESS` / `LOGIN_FAILURE` in `SecurityEvent`.

### 1.2 `POST /api/auth/logout`
- **Purpose:** Immediately revoke the active user session token in PostgreSQL and clear session cookies.
- **Authentication:** Plane 1 (Authenticated User Session).
- **Authorization:** Any authenticated user for their own current session.
- **Request Body:** `{ "revokeAllSessions": false }`
- **Response (`200 OK`):** `{ "status": "logged_out" }`
- **Errors:** `401 Unauthorized` if no valid session is present.
- **Rate Limits:** `30 requests / minute / user`.
- **Audit Requirements:** Writes `USER_LOGOUT` to `AuditLog`.

---

## 2. Devices & Enrollment Group (`/api/devices` — `IMPLEMENTED`)

### 2.1 `GET /api/devices`
- **Purpose:** List all devices owned by the authenticated user (excluding `DECOMMISSIONED` unless `?includeDecommissioned=true`).
- **Authentication:** Plane 1 (Authenticated User Session).
- **Authorization:** User may only read devices where `Device.userId === session.userId`.
- **Request:** Query params: `?lifecycleState=ACTIVE&type=WINDOWS` (optional).
- **Response (`200 OK`):**
  ```json
  {
    "devices": [
      {
        "id": "dev_...",
        "name": "ASUS TUF F16",
        "deviceType": "WINDOWS",
        "lifecycleState": "ACTIVE",
        "connectivityStatus": "ONLINE",
        "currentRiskScore": 2,
        "currentRiskLevel": "LOW",
        "lastHeartbeatAt": "2026-10-06T18:00:00Z"
      }
    ]
  }
  ```
- **Errors:** `401 Unauthorized`.
- **Rate Limits:** `60 requests / minute / user`.
- **Audit Requirements:** Standard access log; no `AuditLog` write for routine read.

### 2.2 `GET /api/devices/:id`
- **Purpose:** Retrieve detailed security posture, public key fingerprint, permission state, and latest `RiskAssessment` for a single owned device.
- **Authentication:** Plane 1 (Authenticated User Session).
- **Authorization:** User must own `Device(:id)`.
- **Request:** Path parameter `:id` (UUID).
- **Response (`200 OK`):** Full `Device` detail object + active `DeviceCredential` public key fingerprint + latest `RiskAssessment`.
- **Errors:** `401 Unauthorized`, `404 Not Found` (returned if device does not exist or belongs to another user to prevent UUID enumeration).
- **Rate Limits:** `60 requests / minute / user`.
- **Audit Requirements:** None.

### 2.3 `POST /api/devices/enrollment`
- **Purpose:** Generate a single-use, 10-minute enrollment token (`ENROLLMENT_PENDING`) or complete key registration (`docs/security/device-enrollment.md`).
- **Authentication:** Plane 1 + Step-Up Auth (for token creation); Enrollment Token + Proof-of-Possession Signature (for device key submission).
- **Authorization:** Authenticated user (to initiate/confirm); holder of valid un-expired enrollment token (to submit public key).
- **Request Body (Initiate Enrollment):**
  ```json
  {
    "action": "INITIATE",
    "proposedDeviceName": "ASUS TUF F16",
    "expectedDeviceType": "WINDOWS"
  }
  ```
- **Response (`201 Created`):**
  ```json
  {
    "deviceId": "dev_...",
    "lifecycleState": "ENROLLMENT_PENDING",
    "enrollmentToken": "VJR-9K4M-7P2Q-8R1T",
    "expiresAt": "2026-10-06T18:30:00Z"
  }
  ```
- **Errors:** `400 Bad Request`, `401 Unauthorized`, `403 Step-Up Required`, `409 Conflict` (duplicate public key fingerprint), `410 Gone` (enrollment token expired).
- **Rate Limits:** `10 requests / hour / user`; `3 failed token submissions / IP / 15m`.
- **Audit Requirements:** Writes `DEVICE_ENROLLMENT_INITIATED`, `DEVICE_KEY_SUBMITTED`, and `DEVICE_ENROLLED` to `AuditLog`.

---

## 3. Security Events Group (`/api/events` — `IMPLEMENTED`)

### 3.1 `GET /api/events`
- **Purpose:** Query the chronological Security Timeline (`docs/product/security-timeline.md`) with filtering and cursor-based pagination.
- **Authentication:** Plane 1 (Authenticated User Session).
- **Authorization:** User may only query events where `SecurityEvent.userId === session.userId`.
- **Request Query Parameters:**
  - `deviceId` (optional UUID)
  - `category` (`AUTHENTICATION` | `DEVICE` | `SECURITY` | `RECOVERY` | `THREATCHECK`)
  - `minSeverity` (`INFO` | `LOW` | `MEDIUM` | `HIGH` | `CRITICAL`)
  - `cursor` (optional event ULID/UUID)
  - `limit` (1–100, default `50`)
- **Response (`200 OK`):**
  ```json
  {
    "events": [ /* Canonical SecurityEvent items */ ],
    "nextCursor": "evt_01J9Z..."
  }
  ```
- **Errors:** `400 Bad Request` (invalid filter enum), `401 Unauthorized`.
- **Rate Limits:** `60 requests / minute / user`.
- **Audit Requirements:** None for routine timeline browsing.

### 3.2 `POST /api/events` (Device Telemetry Ingestion)
- **Purpose:** Ingest signed security events and heartbeats from an enrolled Windows or Android agent.
- **Authentication:** Plane 2 (Cryptographic Device Signature headers `X-Vajra-Device-Id`, `X-Vajra-Timestamp`, `X-Vajra-Nonce`, `X-Vajra-Signature`).
- **Authorization:** Device must be in `TRUSTED`, `ACTIVE`, `OFFLINE`, or `LOST` state (rejected if `REVOKED` or `COMPROMISED`).
- **Request Body:** Signed batch or single `SecurityEvent` payload.
- **Response (`202 Accepted`):** `{ "accepted": true, "eventId": "evt_..." }`.
- **Errors:** `400 Invalid Schema`, `401 Invalid Device Signature`, `403 Device Revoked`, `409 Nonce Replayed`.
- **Rate Limits:** `60 requests / minute / device`.
- **Audit Requirements:** Invalid signatures or replay attempts write `DEVICE_AUTH_ANOMALY` to `AuditLog`.

---

## 4. Alerts Group (`/api/notifications` — `IMPLEMENTED`; legacy `/api/alerts` naming in older docs)

### 4.1 `GET /api/alerts`
- **Purpose:** Retrieve prioritized, deduplicated alerts (`OPEN`, `ACKNOWLEDGED`, `RESOLVED`) for the user's devices.
- **Authentication:** Plane 1 (Authenticated User Session).
- **Authorization:** User may only read their own alerts.
- **Request Query Parameters:** `?status=OPEN&severity=HIGH&deviceId=...`
- **Response (`200 OK`):** `{ "alerts": [ /* Alert objects */ ] }`
- **Errors:** `401 Unauthorized`.
- **Rate Limits:** `60 requests / minute / user`.
- **Audit Requirements:** None.

### 4.2 `POST /api/alerts/:id/acknowledge`
- **Purpose:** Mark an active alert as `ACKNOWLEDGED` (or `RESOLVED`) with an optional user note.
- **Authentication:** Plane 1 (Authenticated User Session).
- **Authorization:** User must own the alert (`Alert.userId === session.userId`).
- **Request Body:**
  ```json
  {
    "resolutionAction": "ACKNOWLEDGE",
    "note": "Verified physical USB flash drive insertion on my desk."
  }
  ```
- **Response (`200 OK`):** Updated `Alert` object with `acknowledgedAt`.
- **Errors:** `401 Unauthorized`, `404 Not Found`.
- **Rate Limits:** `30 requests / minute / user`.
- **Audit Requirements:** Writes `ALERT_ACKNOWLEDGED` to `AuditLog`.

---

## 5. Location Group — `PARTIAL` (command allowlisted; agents do not execute GPS location)

### 5.1 `POST /api/devices/:id/location/request`
- **Purpose:** Request a fresh permission-aware location update from an enrolled device (creates an authorized `REQUEST_LOCATION` command).
- **Authentication:** Plane 1 (User Session) + Plane 3 (Step-Up Auth verified).
- **Authorization:** User must own `Device(:id)`; device must be in `TRUSTED`, `ACTIVE`, `OFFLINE`, or `LOST` state.
- **Request Body:** `{ "reason": "LOCATE_DEVICE" }`
- **Response (`202 Accepted`):**
  ```json
  {
    "commandId": "cmd_...",
    "status": "AUTHORIZED",
    "expiresAt": "2026-10-06T18:25:00Z"
  }
  ```
- **Errors:** `401 Unauthorized`, `403 Step-Up Required` or `Location Disabled By Policy`, `404 Device Not Found`.
- **Rate Limits:** `10 requests / 15 minutes / device`.
- **Audit Requirements:** Writes `LOCATION_REQUEST_AUTHORIZED` to `AuditLog`.

### 5.2 `GET /api/devices/:id/location`
- **Purpose:** Retrieve the most recent decrypted `LocationRecord` for the device along with explicit `LocationSource`, `LocationAccuracy`, `Timestamp`, and `PermissionState`.
- **Authentication:** Plane 1 (User Session) + Plane 3 (Step-Up Auth required to view precise coordinates).
- **Authorization:** User must own `Device(:id)`.
- **Request:** Path param `:id`.
- **Response (`200 OK`):**
  ```json
  {
    "deviceId": "dev_...",
    "permissionState": "GRANTED_BACKGROUND",
    "location": {
      "latitude": 12.9716,
      "longitude": 77.5946,
      "locationSource": "ANDROID_FUSED_GPS",
      "accuracyTier": "PRECISE",
      "accuracyMeters": 14.5,
      "isApproximateIpOnly": false,
      "capturedAt": "2026-10-06T18:20:05Z",
      "batteryPct": 78
    }
  }
  ```
- **Errors:** `401 Unauthorized`, `403 Step-Up Required`, `404 No Location Record Available`.
- **Rate Limits:** `30 requests / minute / user`.
- **Audit Requirements:** Writes `LOCATION_RECORD_VIEWED` to `AuditLog`.

---

## 6. Remote Commands Group (`/api/devices/:id/commands` — `IMPLEMENTED`; receipt-driven)

### 6.1 `POST /api/devices/:id/commands`
- **Purpose:** Issue an allowlisted remote command (`REQUEST_DEVICE_STATUS`, `REQUEST_LOCATION`, `RING_PHONE`, `ENABLE_LOST_MODE`, `DISABLE_LOST_MODE`, `DISPLAY_RECOVERY_MESSAGE`) to a target device.
- **Authentication:** Plane 1 (User Session) + Plane 3 (Step-Up Passkey/MFA assertion required for all commands except `REQUEST_DEVICE_STATUS`).
- **Authorization:**
  - User must own `Device(:id)`.
  - `commandType` must be in the strict allowlist (any attempt to submit `EXECUTE_SHELL`, `EXECUTE_COMMAND`, etc. is rejected with `400 PROHIBITED_CAPABILITY`).
  - Target device must not be `REVOKED` or `COMPROMISED`.
- **Request Body:**
  ```json
  {
    "commandType": "RING_PHONE",
    "parameters": {
      "durationSeconds": 60
    }
  }
  ```
- **Response (`201 Created`):**
  ```json
  {
    "commandId": "cmd_01J9Z9A2...",
    "targetDeviceId": "dev_...",
    "commandType": "RING_PHONE",
    "status": "AUTHORIZED",
    "nonce": "b7f9d2e4a1c385096e4b2d1f8a7c9e02",
    "issuedAt": "2026-10-06T18:15:00Z",
    "expiresAt": "2026-10-06T18:20:00Z",
    "auditLogId": "aud_..."
  }
  ```
- **Errors:** `400 Prohibited or Invalid Command`, `401 Unauthorized`, `403 Step-Up Auth Required`, `404 Device Not Found`, `409 Conflicting Pending Command`.
- **Rate Limits:** `10 commands / 15 minutes / user`.
- **Audit Requirements:** Mandatory synchronous write (`COMMAND_AUTHORIZED`) to `AuditLog` **before** command is queued or dispatched.

### 6.2 `GET /api/commands/:id`
- **Purpose:** Poll or inspect the status, cryptographic metadata, and signed `CommandResult` of a previously issued command.
- **Authentication:** Plane 1 (Authenticated User Session).
- **Authorization:** User must be `requesterUserId` / owner of `targetDeviceId`.
- **Response (`200 OK`):** `RemoteCommand` + nested `CommandResult` (if completed/failed).
- **Errors:** `401 Unauthorized`, `404 Not Found`.
- **Rate Limits:** `60 requests / minute / user`.
- **Audit Requirements:** None for read poll.

---

## 7. ThreatCheck Group (`/api/threatcheck` — `IMPLEMENTED`)

### 7.1 `POST /api/threatcheck/inspect`
- **Purpose:** Perform safe, SSRF-aware lexical, domain, and destination-boundary analysis on a submitted HTTP/HTTPS URL, redact query parameters/fragments, persist `ThreatCheck` + `ThreatIndicator` records atomically, and record sanitized audit/security events (`docs/security/threatcheck-limitations.md`).
- **Authentication:** Plane 1 (Authenticated User Session + `X-CSRF-Token` / Origin verification).
- **Authorization:** Authenticated user; optional `deviceId` must belong to the caller (`404 DEVICE_NOT_FOUND` on cross-user reference).
- **Request Body:**
  ```json
  {
    "url": "https://example.com/login?token=secret123#frag",
    "deviceId": "optional-owned-device-uuid"
  }
  ```
- **Response (`200 OK`):**
  - `analysis`: Legacy UI compatibility preview (`normalizedDisplayUrl`, `hostname`, `verdict`, `summary`, `signals`, `guidance`).
  - `threatCheck`: Persisted record with `id`, `submittedUrlRedacted` (`https://example.com/login?token=[REDACTED]`), `normalizedDomain`, `verdict`, `classification` (`restricted destination` | `suspicious indicators` | `no obvious lexical indicators`), `riskScore` (`0–100`), `restrictedDestination`, `summary`, `recommendedGuidance`, `limitationsStatement`, `checkedAt`, and structured `indicators[]`.
  - `activityId`: Correlated `AuditLog` entry ID.
  - `notification`: Created `NotificationItemDto` when verdict is `SUSPICIOUS` or `HIGH RISK`, otherwise `null`.
- **Errors:** `400 Bad Request` (`INVALID_URL`, `UNSUPPORTED_PROTOCOL`, `EMBEDDED_CREDENTIALS_FORBIDDEN`, `MALFORMED_URL`, `INVALID_HOSTNAME`), `401 Unauthorized`, `403 CSRF Failed`, `404 Device Not Found`.
- **Audit Requirements:** Writes `THREATCHECK_INSPECTED` (with redacted URL only) to `AuditLog` and ingests `THREATCHECK_LOW` / `THREATCHECK_SUSPICIOUS` / `THREATCHECK_HIGH_RISK` into `SecurityEvent`.

### 7.2 `GET /api/threatcheck/history`
- **Purpose:** Retrieve paginated, user-scoped `ThreatCheck` history and nested `ThreatIndicator` lists.
- **Authentication:** Plane 1 (Authenticated User Session).
- **Authorization:** Strictly scoped to `ThreatCheck.userId === session.userId`.
- **Query Parameters:** `limit` (`1..100`, default `25`), `offset` (`>= 0`, default `0`), `verdict` (`LOW RISK` | `SUSPICIOUS` | `HIGH RISK`), `deviceId` (owned device UUID).
- **Response (`200 OK`):** `{ "checks": [ /* ThreatCheck + indicators[] */ ], "pagination": { "limit": 25, "offset": 0, "totalCount": 2, "hasMore": false } }`.
- **Errors:** `400 Bad Request` (`INVALID_PAGINATION`, `INVALID_VERDICT_FILTER`), `401 Unauthorized`, `404 Device Not Found`.

---

## 8. Audit Trail, Analytics & Report Export Group (`/api/audit`, `/api/analytics`, `/api/reports` — `IMPLEMENTED`)

### 8.1 `GET /api/audit`
- **Purpose:** Retrieve the user's tamper-evident, hash-chained security audit trail (`AuditLog`) for transparency and verification.
- **Authentication:** Plane 1 (Authenticated User Session).
- **Authorization:** User may view all `AuditLog` records where `AuditLog.actorUserId === session.userId`.
- **Response (`200 OK`):** `{ "entries": [ /* AuditChainEntry[] */ ], "chainIntegrity": { "valid": true, "checkedCount": 12 } }`.

### 8.2 `GET /api/analytics/summary`
- **Purpose:** Return real, user-scoped security posture metrics derived from persisted devices, security events, notifications/alerts, ThreatCheck inspections, risk assessments, and remote commands (`docs/product/analytics-report.md`).
- **Authentication:** Plane 1 (Authenticated User Session).
- **Authorization:** Strictly scoped to `session.userId`. Never fabricates demo metrics when datasets are empty.
- **Response (`200 OK`):** `{ "summary": { "generatedAt": "...", "accountPosture": {}, "devices": {}, "securityEvents": {}, "alerts": {}, "threatChecks": {}, "remoteCommands": {} } }`.

### 8.3 `GET /api/reports/export`
- **Purpose:** Download a user-scoped security report in JSON (`?format=json`) or formula-injection-safe CSV (`?format=csv`).
- **Authentication:** Plane 1 (Authenticated User Session).
- **Authorization:** Strictly scoped to `session.userId`.
- **Query Parameters:** `format` (`json` | `csv`, default `json`), `limit` (`1..200`, default `100`).
- **Response (`200 OK`):** Attachment with `Content-Type: application/json; charset=utf-8` or `text/csv; charset=utf-8` and `Content-Disposition: attachment; filename="vajra-security-report-YYYY-MM-DD.{json|csv}"`.
- **Audit Requirements:** Appends `SECURITY_REPORT_EXPORTED` to `AuditLog`.


## Auth Step-Up (Prompt 0011D — IMPLEMENTED)

### `POST /api/auth/step-up`
- **Purpose:** Server-side TOTP verification granting a short-lived (5 min), session-bound, action-scoped step-up.
- **Authentication:** Plane 1 session + CSRF.
- **Body:** `{ "totpCode": "123456", "actionScope": "DEVICE_REVOKE" | "DEVICE_COMPROMISED" | "ENABLE_LOST_MODE" | "DISABLE_LOST_MODE" | "SENSITIVE_COMMAND" }`
- **Never accepts** client boolean/timestamp as proof.
- **Protected actions:** device revoke, compromised flag, lost-mode enable/disable, sensitive remote commands.
- **Errors:** `403 STEP_UP_REQUIRED` on protected endpoints when grant is missing/expired/wrong-scope.
- **One-time consumption:** After a successful sensitive operation (revoke, compromised, sensitive action/command), the server clears `stepUpVerifiedUntil` / `stepUpActionScope` so the grant cannot be reused for another action.
- **UI:** Web console opens an MFA step-up dialog on `STEP_UP_REQUIRED`, verifies via this endpoint, then retries the original operation once.


## Analytics & Reports (Prompt 0012)

### `GET /api/analytics/summary`
- **Auth:** Plane 1 session.
- **Returns:** `AnalyticsSummaryDto` with `dataSource: "PERSISTED"`, `windowDescription`, and zero-safe aggregates.
- **Isolation:** Only the authenticated user's devices, events, notifications, ThreatChecks, and commands.

### `GET /api/reports/export?format=json|csv&limit=1..200`
- **Auth:** Plane 1 session.
- **Headers:** `Content-Disposition` attachment, `Cache-Control: no-store`.
- **CSV:** Formula-injection safe cells via `escapeCsvCellSafe`.


## Platform command support (Prompt 0028)

| Command | Windows agent | Android agent |
| :--- | :---: | :---: |
| `REQUEST_DEVICE_STATUS` | Yes | Yes |
| `RING_DEVICE` | No (unsupported result) | Yes |
| `REQUEST_LOCATION` | No | No (deferred) |
| Lost mode / recovery UI | No | No |
| Shell / arbitrary code | Never | Never |

Queued commands are not completed until an authentic device result is persisted.
Demo endpoint `POST /api/demo/events` returns **404 DEMO_DISABLED** when `NODE_ENV`/`APP_ENV` is production.
