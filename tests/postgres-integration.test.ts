/**
 * VAJRA — Real PostgreSQL integration tests (Prompt 0021)
 *
 * Runs only when DATABASE_URL points at a reachable PostgreSQL instance.
 * Uses PrismaIdentityRepository — not the in-memory adapter.
 *
 * Dummy data only. Does not claim Windows/Android agent runtime verification.
 * Prompt 0043 adds battery-telemetry cases against this same PostgreSQL database.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';
import { PrismaClient } from '@prisma/client';
import {
  generateDeviceKeyPair,
  signDeviceRequest,
  signEnrollmentProof,
  generateTotpSecret,
  encryptTotpSecret,
  generateTotpCodeAtTime,
  verifyTotpCode,
  verifyAuditChain,
} from '../packages/security/src/node.ts';
import { createVajraApiApp } from '../src/server/app.ts';
import { PrismaIdentityRepository } from '../src/server/db/repository.ts';
import { STEP_UP_SCOPES } from '../src/server/auth/middleware.ts';
import { BATTERY_HISTORY_RESULT_LIMIT } from '../src/server/notifications/routes.ts';

const DATABASE_URL = process.env.DATABASE_URL?.trim() ?? '';
const TOTP_KEY = 'vajra-pg-integration-totp-key-32b!!';
const RUN_PG =
  (DATABASE_URL.startsWith('postgresql://') || DATABASE_URL.startsWith('postgres://')) &&
  process.env.VAJRA_PG_INTEGRATION === '1';

function extractCookie(setCookie: string | string[] | undefined): string {
  if (!setCookie) return '';
  const raw = Array.isArray(setCookie) ? setCookie[0] : setCookie;
  return raw.split(';')[0] ?? '';
}

async function requestJson(
  server: http.Server,
  options: {
    method: string;
    path: string;
    body?: unknown;
    cookie?: string;
    csrfToken?: string;
    headers?: Record<string, string>;
  }
): Promise<{ status: number; body: any; headers: http.IncomingHttpHeaders }> {
  const addr = server.address();
  assert(addr && typeof addr === 'object');
  const payload = options.body === undefined ? undefined : JSON.stringify(options.body);
  const headers: Record<string, string> = {
    Accept: 'application/json',
    ...(options.headers ?? {}),
  };
  if (payload !== undefined) {
    headers['Content-Type'] = 'application/json';
    headers['Content-Length'] = String(Buffer.byteLength(payload));
  }
  if (options.cookie) headers.Cookie = options.cookie;
  if (options.csrfToken) headers['X-CSRF-Token'] = options.csrfToken;

  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port: addr.port,
        path: options.path,
        method: options.method,
        headers,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let body: unknown = null;
          try {
            body = text ? JSON.parse(text) : null;
          } catch {
            body = { _raw: text };
          }
          resolve({ status: res.statusCode ?? 0, body, headers: res.headers });
        });
      }
    );
    req.on('error', reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

type DeviceKeyPair = ReturnType<typeof generateDeviceKeyPair>;

async function registerOwner(
  server: http.Server,
  email: string,
  displayName: string
): Promise<{ cookie: string; csrf: string; userId: string }> {
  const reg = await requestJson(server, {
    method: 'POST',
    path: '/api/auth/register',
    body: {
      email,
      password: 'PgIntegration-Passw0rd!',
      displayName,
    },
  });
  assert.equal(reg.status, 201, JSON.stringify(reg.body));
  const cookie = extractCookie(reg.headers['set-cookie']);
  const csrf = reg.body.csrfToken as string;
  const userId = reg.body.user.id as string;
  assert.ok(cookie && csrf && userId, JSON.stringify(reg.body));
  return { cookie, csrf, userId };
}

async function enrollConfirmedDevice(
  server: http.Server,
  owner: { cookie: string; csrf: string },
  name: string,
  deviceType: 'ANDROID' | 'WINDOWS'
): Promise<{ deviceId: string; keyPair: DeviceKeyPair }> {
  const init = await requestJson(server, {
    method: 'POST',
    path: '/api/devices/enrollment/initiate',
    cookie: owner.cookie,
    csrfToken: owner.csrf,
    body: { name, deviceType },
  });
  assert.equal(init.status, 201, JSON.stringify(init.body));
  const enrollment = init.body.enrollment;
  const deviceId = enrollment.deviceId as string;
  const enrollmentToken = enrollment.enrollmentToken as string;
  const challengeNonce = enrollment.challengeNonce as string;
  assert.ok(deviceId && enrollmentToken && challengeNonce, JSON.stringify(init.body));

  const keyPair = generateDeviceKeyPair('ED25519');
  const timestampIso = new Date().toISOString();
  const clientNonce = crypto.randomBytes(16).toString('hex');
  const signatureBase64 = signEnrollmentProof({
    privateKeyPem: keyPair.privateKeyPem,
    keyAlgorithm: 'ED25519',
    deviceId,
    enrollmentToken,
    challengeNonce,
    publicKeyFingerprint: keyPair.publicKeyFingerprint,
    timestampIso,
    clientNonce,
  });
  const submit = await requestJson(server, {
    method: 'POST',
    path: '/api/devices/enrollment/submit',
    body: {
      enrollmentToken,
      publicKeyPem: keyPair.publicKeyPem,
      keyAlgorithm: 'ED25519',
      signatureBase64,
      timestampIso,
      clientNonce,
      hardwareBacked: false,
    },
  });
  assert.ok(submit.status === 200 || submit.status === 201, JSON.stringify(submit.body));

  const confirm = await requestJson(server, {
    method: 'POST',
    path: `/api/devices/${deviceId}/enrollment/confirm`,
    cookie: owner.cookie,
    csrfToken: owner.csrf,
  });
  assert.ok(confirm.status === 200 || confirm.status === 201, JSON.stringify(confirm.body));
  return { deviceId, keyPair };
}

function signedDeviceHeaders(
  keyPair: DeviceKeyPair,
  deviceId: string,
  method: string,
  path: string,
  body: unknown
): Record<string, string> {
  const timestampIso = new Date().toISOString();
  const nonce = crypto.randomUUID();
  const signature = signDeviceRequest({
    privateKeyPem: keyPair.privateKeyPem,
    keyAlgorithm: 'ED25519',
    method,
    path,
    deviceId,
    timestampIso,
    nonce,
    body,
  });
  return {
    'X-Vajra-Device-Id': deviceId,
    'X-Vajra-Timestamp': timestampIso,
    'X-Vajra-Nonce': nonce,
    'X-Vajra-Signature': signature,
  };
}

async function postSignedHeartbeat(
  server: http.Server,
  deviceId: string,
  keyPair: DeviceKeyPair,
  body: unknown
) {
  const path = `/api/devices/${deviceId}/heartbeat`;
  return requestJson(server, {
    method: 'POST',
    path,
    body,
    headers: signedDeviceHeaders(keyPair, deviceId, 'POST', path, body),
  });
}

describe(
  'PostgreSQL integration (requires VAJRA_PG_INTEGRATION=1 + DATABASE_URL)',
  {
    skip: !RUN_PG
      ? 'BLOCKED: Missing prerequisite — Set VAJRA_PG_INTEGRATION=1 and a disposable PostgreSQL DATABASE_URL (use `npm run test:pg`)'
      : false,
  },
  () => {
  let prisma: PrismaClient;
  let repo: PrismaIdentityRepository;
  let server: http.Server;
  const suffix = crypto.randomBytes(4).toString('hex');
  const emailA = `pg.owner.a.${suffix}@vajra.test`;
  const emailB = `pg.owner.b.${suffix}@vajra.test`;

  before(async () => {
    prisma = new PrismaClient({ datasources: { db: { url: DATABASE_URL } } });
    await prisma.$connect();
    repo = new PrismaIdentityRepository(prisma);
    const app = createVajraApiApp({
      repository: repo,
      totpEncryptionKey: TOTP_KEY,
    });
    server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  });

  after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    // Best-effort cleanup; AuditLog is append-only so device/user deletes may be constrained
    try {
      await prisma.$disconnect();
    } catch {
      /* ignore */
    }
  });

  it('reports PostgreSQL backend health on readiness', async () => {
    const health = await repo.checkDatabaseHealth(3000);
    assert.equal(health.ok, true);
    assert.equal(health.backend, 'POSTGRESQL_PRISMA');

    const ready = await requestJson(server, { method: 'GET', path: '/api/ready' });
    assert.equal(ready.status, 200);
    assert.ok(ready.body.status === 'ready' || ready.body.ready === true || ready.body.status === 'ok');
  });

  it('registers a user and rejects duplicate email (unique constraint)', async () => {
    const reg = await requestJson(server, {
      method: 'POST',
      path: '/api/auth/register',
      body: {
        email: emailA,
        password: 'PgIntegration-Passw0rd!',
        displayName: 'PG Owner A',
      },
    });
    assert.equal(reg.status, 201, JSON.stringify(reg.body));
    assert.ok(reg.body.user?.id);
    assert.ok(reg.body.csrfToken);

    const dup = await requestJson(server, {
      method: 'POST',
      path: '/api/auth/register',
      body: {
        email: emailA,
        password: 'Another-Passw0rd!',
        displayName: 'Dup',
      },
    });
    assert.ok(dup.status === 409 || dup.status === 400, JSON.stringify(dup.body));
  });

  it('persists session, enables MFA, and grants action-scoped step-up', async () => {
    const regAgain = await requestJson(server, {
      method: 'POST',
      path: '/api/auth/register',
      body: {
        email: `pg.session.${suffix}@vajra.test`,
        password: 'PgIntegration-Passw0rd!',
        displayName: 'Session User',
      },
    });
    assert.equal(regAgain.status, 201, JSON.stringify(regAgain.body));
    const cookie = extractCookie(regAgain.headers['set-cookie']);
    const csrf = regAgain.body.csrfToken as string;
    const userId = regAgain.body.user.id as string;
    assert.ok(cookie && csrf && userId, JSON.stringify(regAgain.body));

    const secretBase32 = generateTotpSecret();
    const encrypted = encryptTotpSecret({
      secretBase32,
      userId,
      encryptionKeyMaterial: TOTP_KEY,
    });
    await repo.updateUserCredential({
      userId,
      totpSecretEncrypted: encrypted,
      totpEnabled: true,
    });

    const code = generateTotpCodeAtTime(secretBase32);
    assert.equal(verifyTotpCode({ secretBase32, code }), true);

    const stepUp = await requestJson(server, {
      method: 'POST',
      path: '/api/auth/step-up',
      cookie,
      csrfToken: csrf,
      body: { totpCode: code, actionScope: STEP_UP_SCOPES.DEVICE_REVOKE },
    });
    assert.equal(stepUp.status, 200, JSON.stringify(stepUp.body));
    assert.equal(stepUp.body.stepUpVerified, true);
    assert.equal(stepUp.body.actionScope, STEP_UP_SCOPES.DEVICE_REVOKE);
  });

  it('enrolls a device through pending → confirm and rejects cross-user access', async () => {
    const reg = await requestJson(server, {
      method: 'POST',
      path: '/api/auth/register',
      body: {
        email: emailB,
        password: 'PgIntegration-Passw0rd!',
        displayName: 'PG Owner B',
      },
    });
    assert.equal(reg.status, 201, JSON.stringify(reg.body));
    const cookie = extractCookie(reg.headers['set-cookie']);
    const csrf = reg.body.csrfToken as string;

    const init = await requestJson(server, {
      method: 'POST',
      path: '/api/devices/enrollment/initiate',
      cookie,
      csrfToken: csrf,
      body: { name: 'PG Test Phone', deviceType: 'ANDROID' },
    });
    assert.equal(init.status, 201, JSON.stringify(init.body));
    const enrollment = init.body.enrollment;
    const deviceId = enrollment.deviceId as string;
    const enrollmentToken = enrollment.enrollmentToken as string;
    const challengeNonce = enrollment.challengeNonce as string;
    assert.ok(deviceId && enrollmentToken && challengeNonce, JSON.stringify(init.body));

    const keyPair = generateDeviceKeyPair('ED25519');
    const timestampIso = new Date().toISOString();
    const clientNonce = crypto.randomBytes(16).toString('hex');
    const signatureBase64 = signEnrollmentProof({
      privateKeyPem: keyPair.privateKeyPem,
      keyAlgorithm: 'ED25519',
      deviceId,
      enrollmentToken,
      challengeNonce,
      publicKeyFingerprint: keyPair.publicKeyFingerprint,
      timestampIso,
      clientNonce,
    });

    const submit = await requestJson(server, {
      method: 'POST',
      path: '/api/devices/enrollment/submit',
      body: {
        enrollmentToken,
        publicKeyPem: keyPair.publicKeyPem,
        keyAlgorithm: 'ED25519',
        signatureBase64,
        timestampIso,
        clientNonce,
        hardwareBacked: false,
      },
    });
    assert.ok(submit.status === 200 || submit.status === 201, JSON.stringify(submit.body));

    const confirm = await requestJson(server, {
      method: 'POST',
      path: `/api/devices/${deviceId}/enrollment/confirm`,
      cookie,
      csrfToken: csrf,
    });
    assert.ok(confirm.status === 200 || confirm.status === 201, JSON.stringify(confirm.body));

    // Cross-user: register C and attempt to read B's device
    const regC = await requestJson(server, {
      method: 'POST',
      path: '/api/auth/register',
      body: {
        email: `pg.owner.c.${suffix}@vajra.test`,
        password: 'PgIntegration-Passw0rd!',
        displayName: 'PG Owner C',
      },
    });
    assert.equal(regC.status, 201);
    const cookieC = extractCookie(regC.headers['set-cookie']);
    const getCross = await requestJson(server, {
      method: 'GET',
      path: `/api/devices/${deviceId}`,
      cookie: cookieC,
    });
    assert.ok(getCross.status === 404 || getCross.status === 403, JSON.stringify(getCross.body));

    // Heartbeat persistence via signed Plane-2 request
    const hbPath = `/api/devices/${deviceId}/heartbeat`;
    const hbBody = { connectivityStatus: 'ONLINE', agentVersion: '0.1.0-test' };
    const ts = new Date().toISOString();
    const nonce = crypto.randomUUID();
    const sig = signDeviceRequest({
      privateKeyPem: keyPair.privateKeyPem,
      keyAlgorithm: 'ED25519',
      method: 'POST',
      path: hbPath,
      deviceId,
      timestampIso: ts,
      nonce,
      body: hbBody,
    });
    const hb = await requestJson(server, {
      method: 'POST',
      path: hbPath,
      body: hbBody,
      headers: {
        'X-Vajra-Device-Id': deviceId,
        'X-Vajra-Timestamp': ts,
        'X-Vajra-Nonce': nonce,
        'X-Vajra-Signature': sig,
      },
    });
    assert.ok(hb.status === 200 || hb.status === 201, JSON.stringify(hb.body));

    const deviceRow = await prisma.device.findUnique({ where: { id: deviceId } });
    assert.ok(deviceRow);
    assert.ok(deviceRow.lastHeartbeatAt || deviceRow.lastSeenAt);

    const hbRow = await prisma.deviceHeartbeat.findFirst({ where: { deviceId } });
    assert.ok(hbRow, 'expected persisted DeviceHeartbeat row in PostgreSQL');

    const nonceRow = await prisma.deviceAuthNonce.findFirst({ where: { deviceId, nonce } });
    assert.ok(nonceRow, 'expected persisted DeviceAuthNonce row in PostgreSQL');

    // Replay of the same nonce must be rejected with 409 DEVICE_NONCE_REPLAYED
    const replay = await requestJson(server, {
      method: 'POST',
      path: hbPath,
      body: hbBody,
      headers: {
        'X-Vajra-Device-Id': deviceId,
        'X-Vajra-Timestamp': ts,
        'X-Vajra-Nonce': nonce,
        'X-Vajra-Signature': sig,
      },
    });
    assert.equal(replay.status, 409, JSON.stringify(replay.body));
    assert.equal(replay.body?.error?.code, 'DEVICE_NONCE_REPLAYED');

    // Queue REQUEST_DEVICE_STATUS -> poll -> ack -> result receipt persisted in PostgreSQL
    const createCmd = await requestJson(server, {
      method: 'POST',
      path: `/api/devices/${deviceId}/commands`,
      cookie,
      csrfToken: csrf,
      body: { actionType: 'REQUEST_DEVICE_STATUS', ttlMinutes: 30 },
    });
    assert.equal(createCmd.status, 201, JSON.stringify(createCmd.body));
    const commandId = createCmd.body.command?.id as string;
    assert.ok(commandId);

    const pollPath = `/api/devices/${deviceId}/commands/pending`;
    const pollTs = new Date().toISOString();
    const pollNonce = crypto.randomUUID();
    const pollSig = signDeviceRequest({
      privateKeyPem: keyPair.privateKeyPem,
      keyAlgorithm: 'ED25519',
      method: 'GET',
      path: pollPath,
      deviceId,
      timestampIso: pollTs,
      nonce: pollNonce,
      body: undefined,
    });
    const pendingRes = await requestJson(server, {
      method: 'GET',
      path: pollPath,
      headers: {
        'X-Vajra-Device-Id': deviceId,
        'X-Vajra-Timestamp': pollTs,
        'X-Vajra-Nonce': pollNonce,
        'X-Vajra-Signature': pollSig,
      },
    });
    assert.equal(pendingRes.status, 200, JSON.stringify(pendingRes.body));
    assert.ok(
      Array.isArray(pendingRes.body.commands) &&
        pendingRes.body.commands.some((c: any) => c.id === commandId)
    );

    const ackPath = `/api/devices/${deviceId}/commands/${commandId}/acknowledge`;
    const ackBody = { message: 'Acknowledged by PG test protocol client' };
    const ackTs = new Date().toISOString();
    const ackNonce = crypto.randomUUID();
    const ackSig = signDeviceRequest({
      privateKeyPem: keyPair.privateKeyPem,
      keyAlgorithm: 'ED25519',
      method: 'POST',
      path: ackPath,
      deviceId,
      timestampIso: ackTs,
      nonce: ackNonce,
      body: ackBody,
    });
    const ackRes = await requestJson(server, {
      method: 'POST',
      path: ackPath,
      body: ackBody,
      headers: {
        'X-Vajra-Device-Id': deviceId,
        'X-Vajra-Timestamp': ackTs,
        'X-Vajra-Nonce': ackNonce,
        'X-Vajra-Signature': ackSig,
      },
    });
    assert.ok(ackRes.status === 200 || ackRes.status === 201, JSON.stringify(ackRes.body));

    const resultPath = `/api/devices/${deviceId}/commands/${commandId}/result`;
    const resultBody = {
      status: 'COMPLETED',
      safeMessage: 'Status check completed and persisted in PostgreSQL.',
      executionLatencyMs: 25,
      metadata: { posture: 'HEALTHY' },
    };
    const resultTs = new Date().toISOString();
    const resultNonce = crypto.randomUUID();
    const resultSig = signDeviceRequest({
      privateKeyPem: keyPair.privateKeyPem,
      keyAlgorithm: 'ED25519',
      method: 'POST',
      path: resultPath,
      deviceId,
      timestampIso: resultTs,
      nonce: resultNonce,
      body: resultBody,
    });
    const resultRes = await requestJson(server, {
      method: 'POST',
      path: resultPath,
      body: resultBody,
      headers: {
        'X-Vajra-Device-Id': deviceId,
        'X-Vajra-Timestamp': resultTs,
        'X-Vajra-Nonce': resultNonce,
        'X-Vajra-Signature': resultSig,
      },
    });
    assert.ok(resultRes.status === 200 || resultRes.status === 201, JSON.stringify(resultRes.body));

    const persistedCmd = await prisma.remoteCommand.findUnique({ where: { id: commandId } });
    assert.ok(persistedCmd);
    assert.equal(persistedCmd.status, 'COMPLETED');

    const persistedReceipt = await prisma.commandResult.findUnique({ where: { commandId } });
    assert.ok(persistedReceipt, 'expected persisted CommandResult row in PostgreSQL');
    assert.equal(persistedReceipt.status, 'COMPLETED');
  });

  it('returns analytics from persisted records with PERSISTED dataSource', async () => {
    const reg = await requestJson(server, {
      method: 'POST',
      path: '/api/auth/register',
      body: {
        email: `pg.analytics.${suffix}@vajra.test`,
        password: 'PgIntegration-Passw0rd!',
        displayName: 'Analytics User',
      },
    });
    assert.equal(reg.status, 201);
    const cookie = extractCookie(reg.headers['set-cookie']);
    const csrf = reg.body.csrfToken as string;

    const tc = await requestJson(server, {
      method: 'POST',
      path: '/api/threatcheck/inspect',
      cookie,
      csrfToken: csrf,
      body: { url: 'http://127.0.0.1:8080/admin?access_token=SECRET123#frag' },
    });
    assert.equal(tc.status, 200, JSON.stringify(tc.body));

    const res = await requestJson(server, {
      method: 'GET',
      path: '/api/analytics/summary',
      cookie,
    });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(res.body.summary?.dataSource, 'PERSISTED');
    assert.ok(typeof res.body.summary?.devices?.totalCount === 'number');
    assert.ok(res.body.summary?.threatChecks?.totalCount >= 1, JSON.stringify(res.body.summary));
  });

  it('enforces append-only AuditLog at the database layer', async () => {
    const rows = await prisma.auditLog.findMany({ take: 1 });
    assert.ok(rows.length > 0, 'expected persisted AuditLog rows in PostgreSQL');
    const id = rows[0].id;
    let updateRejected = false;
    try {
      await prisma.$executeRawUnsafe(
        `UPDATE "AuditLog" SET "eventType" = 'TAMPER' WHERE id = $1::uuid`,
        id
      );
    } catch (err) {
      updateRejected = true;
      const msg = String(err);
      assert.match(msg, /VAJRA_AUDIT_IMMUTABLE|append-only|AuditLog/i);
    }
    assert.equal(updateRejected, true, 'expected AuditLog UPDATE to be rejected by trigger');

    let deleteRejected = false;
    try {
      await prisma.$executeRawUnsafe(
        `DELETE FROM "AuditLog" WHERE id = $1::uuid`,
        id
      );
    } catch (err) {
      deleteRejected = true;
      const msg = String(err);
      assert.match(msg, /VAJRA_AUDIT_IMMUTABLE|append-only|AuditLog/i);
    }
    assert.equal(deleteRejected, true, 'expected AuditLog DELETE to be rejected by trigger');

    const allOrdered = await repo.getAllAuditEventsOrdered();
    const chainVerification = verifyAuditChain(allOrdered);
    assert.equal(chainVerification.valid, true, JSON.stringify(chainVerification));
  });

  it('persists signed Android battery telemetry and enforces history rules', async () => {
    const owner = await registerOwner(
      server,
      `pg.battery.owner.${suffix}@vajra.test`,
      'PG Battery Owner'
    );
    const other = await registerOwner(
      server,
      `pg.battery.other.${suffix}@vajra.test`,
      'PG Battery Other'
    );
    const android = await enrollConfirmedDevice(
      server,
      owner,
      'PG Battery Phone',
      'ANDROID'
    );
    const windows = await enrollConfirmedDevice(
      server,
      owner,
      'PG Battery Laptop',
      'WINDOWS'
    );

    try {
      const emptyHistory = await requestJson(server, {
        method: 'GET',
        path: `/api/devices/${android.deviceId}/battery-history`,
        cookie: owner.cookie,
      });
      assert.equal(emptyHistory.status, 200, JSON.stringify(emptyHistory.body));
      assert.equal(emptyHistory.body.platform, 'ANDROID');
      assert.equal(emptyHistory.body.hasTelemetry, false);
      assert.deepEqual(emptyHistory.body.readings, []);
      assert.equal(emptyHistory.body.currentLevel, null);
      assert.equal(emptyHistory.body.charging, null);

      const omitted = await postSignedHeartbeat(server, android.deviceId, android.keyPair, {
        connectivityStatus: 'ONLINE',
        agentVersion: '0.1.0-no-battery',
      });
      assert.equal(omitted.status, 200, JSON.stringify(omitted.body));
      assert.equal(omitted.body.heartbeat.batteryLevel, null);
      assert.equal(omitted.body.heartbeat.charging, null);

      const omittedRow = await prisma.deviceHeartbeat.findFirst({
        where: { deviceId: android.deviceId, agentVersion: '0.1.0-no-battery' },
      });
      assert.ok(omittedRow, 'expected a persisted heartbeat when battery fields are omitted');
      assert.equal(omittedRow.batteryLevel, null);
      assert.equal(omittedRow.charging, null);

      const omittedHistory = await requestJson(server, {
        method: 'GET',
        path: `/api/devices/${android.deviceId}/battery-history`,
        cookie: owner.cookie,
      });
      assert.equal(omittedHistory.status, 200, JSON.stringify(omittedHistory.body));
      assert.equal(omittedHistory.body.hasTelemetry, false);
      assert.deepEqual(omittedHistory.body.readings, []);
      assert.equal(omittedHistory.body.currentLevel, null);
      assert.equal(omittedHistory.body.charging, null);

      const beforeInvalid = await prisma.deviceHeartbeat.count({
        where: { deviceId: android.deviceId },
      });
      const tooHigh = await postSignedHeartbeat(server, android.deviceId, android.keyPair, {
        connectivityStatus: 'ONLINE',
        batteryLevel: 150,
        charging: false,
      });
      assert.equal(tooHigh.status, 400, JSON.stringify(tooHigh.body));
      assert.equal(tooHigh.body?.error?.code, 'INVALID_BATTERY_LEVEL');

      const negative = await postSignedHeartbeat(server, android.deviceId, android.keyPair, {
        connectivityStatus: 'ONLINE',
        batteryLevel: -1,
        charging: true,
      });
      assert.equal(negative.status, 400, JSON.stringify(negative.body));
      assert.equal(negative.body?.error?.code, 'INVALID_BATTERY_LEVEL');

      const badCharging = await postSignedHeartbeat(server, android.deviceId, android.keyPair, {
        connectivityStatus: 'ONLINE',
        batteryLevel: 80,
        charging: 'yes',
      });
      assert.equal(badCharging.status, 400, JSON.stringify(badCharging.body));
      assert.equal(badCharging.body?.error?.code, 'INVALID_CHARGING_STATE');

      const afterInvalid = await prisma.deviceHeartbeat.count({
        where: { deviceId: android.deviceId },
      });
      assert.equal(afterInvalid, beforeInvalid, 'invalid telemetry must not be persisted');
      const illegalLevels = await prisma.deviceHeartbeat.count({
        where: {
          deviceId: android.deviceId,
          OR: [{ batteryLevel: { gt: 100 } }, { batteryLevel: { lt: 0 } }],
        },
      });
      assert.equal(illegalLevels, 0);
      const rejectedChargingRow = await prisma.deviceHeartbeat.count({
        where: { deviceId: android.deviceId, batteryLevel: 80 },
      });
      assert.equal(rejectedChargingRow, 0);

      // Age the omission heartbeat so it does not consume the history limit.
      await prisma.deviceHeartbeat.update({
        where: { id: omittedRow.id },
        data: { receivedAt: new Date(Date.now() - 30 * 60 * 60 * 1000) },
      });

      const limit = BATTERY_HISTORY_RESULT_LIMIT;
      assert.equal(limit, 100);
      const anchor = Date.now();
      const stale = await repo.createDeviceHeartbeat({
        deviceId: android.deviceId,
        receivedAt: new Date(anchor - 26 * 60 * 60 * 1000),
        batteryLevel: 17,
        charging: true,
        agentVersion: 'fixture-stale',
      });
      const overflow = await repo.createDeviceHeartbeat({
        deviceId: android.deviceId,
        receivedAt: new Date(anchor - (limit + 5) * 1000),
        batteryLevel: 15,
        charging: false,
        agentVersion: 'fixture-overflow',
      });
      for (let i = 0; i < limit - 1; i++) {
        await repo.createDeviceHeartbeat({
          deviceId: android.deviceId,
          receivedAt: new Date(anchor - (limit - i) * 1000),
          batteryLevel: (i % 90) + 1,
          charging: i % 2 === 0,
          agentVersion: 'fixture-window',
        });
      }

      const validBody = {
        connectivityStatus: 'ONLINE',
        batteryLevel: 64,
        charging: true,
        networkType: 'WIFI',
        agentVersion: '0.1.0-battery',
      };
      const valid = await postSignedHeartbeat(
        server,
        android.deviceId,
        android.keyPair,
        validBody
      );
      assert.equal(valid.status, 200, JSON.stringify(valid.body));
      assert.equal(valid.body.heartbeat.batteryLevel, 64);
      assert.equal(valid.body.heartbeat.charging, true);

      const persisted = await prisma.deviceHeartbeat.findFirst({
        where: {
          deviceId: android.deviceId,
          agentVersion: '0.1.0-battery',
          batteryLevel: 64,
          charging: true,
        },
      });
      assert.ok(persisted, 'expected persisted DeviceHeartbeat batteryLevel=64 charging=true');

      const history = await requestJson(server, {
        method: 'GET',
        path: `/api/devices/${android.deviceId}/battery-history`,
        cookie: owner.cookie,
      });
      assert.equal(history.status, 200, JSON.stringify(history.body));
      assert.equal(history.body.hasTelemetry, true);
      assert.equal(history.body.currentLevel, 64);
      assert.equal(history.body.charging, true);
      const readings = history.body.readings as Array<{
        timestamp: string;
        batteryLevel: number;
        charging: boolean;
      }>;
      assert.equal(readings.length, limit);
      const staleIso = stale.receivedAt.toISOString();
      const overflowIso = overflow.receivedAt.toISOString();
      assert.equal(
        readings.some((reading) => reading.timestamp === staleIso),
        false,
        'readings older than 24 hours must be excluded'
      );
      assert.equal(
        readings.some((reading) => reading.timestamp === overflowIso),
        false,
        'history must drop rows beyond the configured result limit'
      );
      const windowFloor = Date.now() - 24 * 60 * 60 * 1000;
      for (let i = 0; i < readings.length; i++) {
        const reading = readings[i];
        assert.equal(typeof reading.batteryLevel, 'number');
        assert.ok(reading.batteryLevel >= 0 && reading.batteryLevel <= 100);
        assert.equal(typeof reading.charging, 'boolean');
        const at = Date.parse(reading.timestamp);
        assert.ok(at >= windowFloor, `reading ${reading.timestamp} is outside the 24-hour window`);
        if (i > 0) {
          assert.ok(at >= Date.parse(readings[i - 1].timestamp), 'readings must be chronological');
        }
      }
      const latestReading = readings[readings.length - 1];
      assert.equal(latestReading.batteryLevel, 64);
      assert.equal(latestReading.charging, true);
      assert.equal(latestReading.timestamp, persisted.receivedAt.toISOString());

      const retained = await prisma.deviceHeartbeat.findMany({
        where: { id: { in: [stale.id, overflow.id, omittedRow.id] } },
      });
      assert.equal(retained.length, 3, 'excluded rows must remain stored and simply be unlisted');

      const crossUser = await requestJson(server, {
        method: 'GET',
        path: `/api/devices/${android.deviceId}/battery-history`,
        cookie: other.cookie,
      });
      assert.equal(crossUser.status, 404, JSON.stringify(crossUser.body));
      assert.equal(crossUser.body?.error?.code, 'DEVICE_NOT_FOUND');

      const windowsHistory = await requestJson(server, {
        method: 'GET',
        path: `/api/devices/${windows.deviceId}/battery-history`,
        cookie: owner.cookie,
      });
      assert.equal(windowsHistory.status, 400, JSON.stringify(windowsHistory.body));
      assert.equal(windowsHistory.body?.error?.code, 'UNSUPPORTED_PLATFORM');
    } finally {
      await prisma.deviceHeartbeat.deleteMany({
        where: { deviceId: { in: [android.deviceId, windows.deviceId] } },
      });
    }
  });
});

describe('Production fail-closed configuration (source-level)', () => {
  it('server.ts rejects production without a real DATABASE_URL', async () => {
    const fs = await import('node:fs');
    const path = await import('node:path');
    const src = fs.readFileSync(path.join(process.cwd(), 'server.ts'), 'utf8');
    assert.match(src, /In-memory fallback is disabled/);
    assert.match(src, /Production requires a non-placeholder DATABASE_URL/);
    assert.match(src, /Production refuses to start without a healthy database/);
  });
});
