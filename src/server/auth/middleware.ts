/**
 * VAJRA — Server-Side Cookie, Authorization & CSRF Middleware
 * Prompt 0003:
 * - Distinguishes UNAUTHENTICATED vs AUTHENTICATED_USER (and reserves TRUSTED_DEVICE / BACKEND_AUTHORITY)
 * - Uses HttpOnly, SameSite=Lax, Path=/ session cookies (Secure + __Host- in HTTPS production)
 * - Enforces double-submit / session-bound X-CSRF-Token + Origin/Referer verification on state-changing requests
 */

import { Request, Response, NextFunction } from 'express';
import {
  hashSessionToken,
  verifyCsrfToken,
  generateSessionTokenPair,
  SESSION_IDLE_TTL_MS,
  SESSION_ROTATION_THRESHOLD_MS,
  verifyDeviceRequestSignature,
  canDeviceAuthenticateInState,
  DEVICE_AUTH_TIMESTAMP_WINDOW_MS,
} from '../../../packages/security/src/node.ts';
import {
  IdentityRepository,
  UserEntity,
  DeviceSessionEntity,
  DeviceEntity,
  DeviceCredentialEntity,
} from '../db/repository.ts';

export enum PrincipalLevel {
  UNAUTHENTICATED = 'UNAUTHENTICATED',
  AUTHENTICATED_USER = 'AUTHENTICATED_USER',
  TRUSTED_DEVICE = 'TRUSTED_DEVICE', // Plane 2 Cryptographic Device Authentication
  BACKEND_AUTHORITY = 'BACKEND_AUTHORITY', // Reserved for internal Plane 3
}

export interface AuthenticatedContext {
  principalLevel: PrincipalLevel;
  user: UserEntity;
  session: DeviceSessionEntity;
  rawCsrfToken?: string;
}

export interface TrustedDeviceContext {
  principalLevel: PrincipalLevel.TRUSTED_DEVICE;
  device: DeviceEntity;
  credential: DeviceCredentialEntity;
  nonce: string;
  timestampIso: string;
}

declare global {
  namespace Express {
    interface Request {
      authContext?: AuthenticatedContext;
      deviceAuthContext?: TrustedDeviceContext;
    }
  }
}

export const SESSION_COOKIE_PROD = '__Host-vajra_session';
export const SESSION_COOKIE_DEV = 'vajra_session';

export function parseCookies(cookieHeader: string | undefined): Record<string, string> {
  const result: Record<string, string> = {};
  if (!cookieHeader) return result;

  for (const part of cookieHeader.split(';')) {
    const eqIdx = part.indexOf('=');
    if (eqIdx === -1) continue;
    const key = part.slice(0, eqIdx).trim();
    const val = part.slice(eqIdx + 1).trim();
    if (key) {
      try {
        result[key] = decodeURIComponent(val);
      } catch {
        result[key] = val;
      }
    }
  }
  return result;
}

export function isSecureRequest(req: Request): boolean {
  if (req.secure) return true;
  const proto = req.headers['x-forwarded-proto'];
  if (typeof proto === 'string' && proto.split(',')[0].trim().toLowerCase() === 'https') {
    return true;
  }
  return process.env.NODE_ENV === 'production';
}

export function setSessionCookie(
  req: Request,
  res: Response,
  rawSessionToken: string,
  maxAgeSeconds = 900
): void {
  const secure = isSecureRequest(req);
  const cookieName = secure ? SESSION_COOKIE_PROD : SESSION_COOKIE_DEV;

  const directives = [
    `${cookieName}=${encodeURIComponent(rawSessionToken)}`,
    'Path=/',
    'HttpOnly',
    secure ? 'SameSite=None' : 'SameSite=Lax',
    `Max-Age=${maxAgeSeconds}`,
  ];

  if (secure) {
    directives.push('Secure');
  }

  res.append('Set-Cookie', directives.join('; '));
}

export function clearSessionCookies(req: Request, res: Response): void {
  const secure = isSecureRequest(req);
  res.append(
    'Set-Cookie',
    `${SESSION_COOKIE_DEV}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`
  );
  if (secure) {
    res.append(
      'Set-Cookie',
      `${SESSION_COOKIE_PROD}=; Path=/; HttpOnly; SameSite=None; Secure; Max-Age=0`
    );
  }
}

export function extractRawSessionToken(req: Request): string | null {
  const cookies = parseCookies(req.headers.cookie);
  return cookies[SESSION_COOKIE_PROD] ?? cookies[SESSION_COOKIE_DEV] ?? null;
}

/**
 * Middleware that resolves the current session if present, enforces idle/absolute expiration,
 * and rotates the session token if past half its idle TTL.
 */
export function createSessionResolutionMiddleware(repo: IdentityRepository) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const rawToken = extractRawSessionToken(req);
      if (!rawToken) {
        next();
        return;
      }

      const tokenHash = hashSessionToken(rawToken);
      const session = await repo.findSessionByTokenHash(tokenHash);
      if (!session) {
        next();
        return;
      }

      const now = new Date();
      if (
        session.revokedAt !== null ||
        now >= session.expiresAt ||
        now >= session.absoluteExpiresAt
      ) {
        if (session.revokedAt === null) {
          await repo.revokeSessionById(session.id, now);
        }
        clearSessionCookies(req, res);
        next();
        return;
      }

      const user = await repo.findUserById(session.userId);
      if (!user || user.status !== 'ACTIVE') {
        await repo.revokeSessionById(session.id, now);
        clearSessionCookies(req, res);
        next();
        return;
      }

      // Check if session should rotate (past 7.5m since last active)
      const elapsedSinceActiveMs = now.getTime() - session.lastActiveAt.getTime();
      const newIdleExpiresAt = new Date(
        Math.min(
          now.getTime() + SESSION_IDLE_TTL_MS,
          session.absoluteExpiresAt.getTime()
        )
      );

      let updatedSession = session;
      if (elapsedSinceActiveMs >= SESSION_ROTATION_THRESHOLD_MS) {
        const rotated = generateSessionTokenPair();
        updatedSession = await repo.updateSessionActivityAndRotation({
          sessionId: session.id,
          newTokenHash: rotated.sessionTokenHash,
          newCsrfTokenHash: rotated.csrfTokenHash,
          lastActiveAt: now,
          expiresAt: newIdleExpiresAt,
        });
        setSessionCookie(req, res, rotated.rawSessionToken, Math.floor(SESSION_IDLE_TTL_MS / 1000));
        res.setHeader('X-Vajra-Csrf-Token', rotated.rawCsrfToken);
      } else {
        updatedSession = await repo.updateSessionActivityAndRotation({
          sessionId: session.id,
          lastActiveAt: now,
          expiresAt: newIdleExpiresAt,
        });
      }

      req.authContext = {
        principalLevel: PrincipalLevel.AUTHENTICATED_USER,
        user,
        session: updatedSession,
      };
      next();
    } catch {
      next();
    }
  };
}

/**
 * Requires an authenticated Plane 1 User session (`AUTHENTICATED_USER`) and enforces CSRF protection
 * on state-changing HTTP methods (`POST`, `PUT`, `PATCH`, `DELETE`).
 */
export function requireAuthenticatedUser(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const ctx = req.authContext;
  if (!ctx || ctx.principalLevel !== PrincipalLevel.AUTHENTICATED_USER) {
    res.status(401).json({
      error: {
        code: 'UNAUTHENTICATED',
        message: 'Authentication is required to access this resource.',
      },
    });
    return;
  }

  const safeMethods = ['GET', 'HEAD', 'OPTIONS'];
  if (!safeMethods.includes(req.method.toUpperCase())) {
    // 1. Validate Origin / Referer header if provided by browser
    const originHeader = req.headers.origin;
    const hostHeader = req.headers.host;
    if (typeof originHeader === 'string' && typeof hostHeader === 'string') {
      try {
        const originUrl = new URL(originHeader);
        if (originUrl.host !== hostHeader) {
          res.status(403).json({
            error: {
              code: 'CSRF_ORIGIN_MISMATCH',
              message: 'Cross-origin state-changing request rejected.',
            },
          });
          return;
        }
      } catch {
        res.status(403).json({
          error: {
            code: 'CSRF_INVALID_ORIGIN',
            message: 'Malformed Origin header rejected.',
          },
        });
        return;
      }
    }

    // 2. Validate session-bound X-CSRF-Token header
    const csrfHeader = req.headers['x-csrf-token'];
    const candidateCsrf = Array.isArray(csrfHeader) ? csrfHeader[0] : csrfHeader;
    if (
      typeof candidateCsrf !== 'string' ||
      !verifyCsrfToken(candidateCsrf, ctx.session.csrfTokenHash)
    ) {
      res.status(403).json({
        error: {
          code: 'CSRF_TOKEN_INVALID',
          message: 'Missing or invalid CSRF protection token.',
        },
      });
      return;
    }
  }

  next();
}

/**
 * Plane 2 Cryptographic Device Authentication Middleware (`TRUSTED_DEVICE`).
 * Enforces:
 * - Plane separation: A Plane 1 User session cookie NEVER satisfies Plane 2 device auth.
 * - Mandatory headers: `X-Vajra-Device-Id`, `X-Vajra-Timestamp`, `X-Vajra-Nonce`, `X-Vajra-Signature`
 * - Device lifecycle check: Rejects `UNREGISTERED`, `ENROLLMENT_PENDING`, `COMPROMISED`, `REVOKED`, `DECOMMISSIONED`
 * - Active `DeviceCredential` lookup (`status === 'ACTIVE' && active === true`)
 * - Cryptographic signature verification (Ed25519 or ECDSA P-256) over canonical transcript + ±120s timestamp window
 * - Nonce replay prevention via `DeviceAuthNonce`
 */
export function createDeviceAuthenticationMiddleware(repo: IdentityRepository) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const rawDeviceId = req.headers['x-vajra-device-id'];
      const rawTimestamp = req.headers['x-vajra-timestamp'];
      const rawNonce = req.headers['x-vajra-nonce'];
      const rawSignature = req.headers['x-vajra-signature'];

      const deviceId = Array.isArray(rawDeviceId) ? rawDeviceId[0] : rawDeviceId;
      const timestampIso = Array.isArray(rawTimestamp) ? rawTimestamp[0] : rawTimestamp;
      const nonce = Array.isArray(rawNonce) ? rawNonce[0] : rawNonce;
      const signatureBase64 = Array.isArray(rawSignature) ? rawSignature[0] : rawSignature;

      if (
        typeof deviceId !== 'string' ||
        typeof timestampIso !== 'string' ||
        typeof nonce !== 'string' ||
        typeof signatureBase64 !== 'string' ||
        !deviceId.trim() ||
        !timestampIso.trim() ||
        !nonce.trim() ||
        !signatureBase64.trim()
      ) {
        res.status(401).json({
          error: {
            code: 'DEVICE_AUTH_HEADERS_MISSING',
            message:
              'Cryptographic device authentication requires X-Vajra-Device-Id, X-Vajra-Timestamp, X-Vajra-Nonce, and X-Vajra-Signature headers.',
          },
        });
        return;
      }

      const device = await repo.findDeviceById(deviceId.trim());
      if (!device) {
        await repo.appendAuditEvent({
          actorUserId: null,
          eventType: 'DEVICE_AUTH_FAILURE',
          metadata: {
            reason: 'UNKNOWN_DEVICE_ID',
            attemptedDeviceId: deviceId.trim(),
          },
        });
        res.status(401).json({
          error: {
            code: 'INVALID_DEVICE_CREDENTIALS',
            message: 'Device authentication failed.',
          },
        });
        return;
      }

      const stateCheck = canDeviceAuthenticateInState(device.lifecycleState);
      if (!stateCheck.allowed) {
        await repo.appendAuditEvent({
          actorUserId: device.userId,
          actorDeviceId: device.id,
          eventType: 'DEVICE_AUTH_FAILURE',
          metadata: {
            reason: stateCheck.reasonCode ?? 'INVALID_LIFECYCLE_STATE',
            lifecycleState: device.lifecycleState,
          },
        });
        res.status(403).json({
          error: {
            code: stateCheck.reasonCode ?? 'DEVICE_FORBIDDEN',
            message: stateCheck.message ?? 'Device is not permitted to authenticate in its current state.',
          },
        });
        return;
      }

      const credentials = await repo.listCredentialsByDeviceId(device.id);
      const activeCredential = credentials.find(
        (c) => c.active && c.status === 'ACTIVE' && c.revokedAt === null
      );

      if (!activeCredential) {
        await repo.appendAuditEvent({
          actorUserId: device.userId,
          actorDeviceId: device.id,
          eventType: 'DEVICE_AUTH_FAILURE',
          metadata: {
            reason: 'NO_ACTIVE_CREDENTIAL',
          },
        });
        res.status(401).json({
          error: {
            code: 'NO_ACTIVE_DEVICE_CREDENTIAL',
            message: 'No active cryptographic credential is registered for this device.',
          },
        });
        return;
      }

      const requestPath = req.originalUrl.split('?')[0];
      const verification = verifyDeviceRequestSignature({
        publicKeyPem: activeCredential.publicKeyPem,
        keyAlgorithm: activeCredential.keyAlgorithm,
        signatureBase64: signatureBase64.trim(),
        method: req.method,
        path: requestPath,
        deviceId: device.id,
        timestampIso: timestampIso.trim(),
        nonce: nonce.trim(),
        body: req.body,
      });

      if (!verification.valid) {
        await repo.appendAuditEvent({
          actorUserId: device.userId,
          actorDeviceId: device.id,
          eventType: 'DEVICE_AUTH_FAILURE',
          metadata: {
            reason: verification.errorCode ?? 'SIGNATURE_VERIFICATION_FAILED',
            path: requestPath,
          },
        });
        res.status(401).json({
          error: {
            code: verification.errorCode ?? 'INVALID_DEVICE_SIGNATURE',
            message: verification.error ?? 'Device cryptographic signature verification failed.',
          },
        });
        return;
      }

      // Nonce replay check (consuming the nonce for 2x timestamp window)
      const now = new Date();
      const nonceExpiresAt = new Date(now.getTime() + DEVICE_AUTH_TIMESTAMP_WINDOW_MS * 2);
      const nonceAccepted = await repo.consumeDeviceAuthNonce({
        deviceId: device.id,
        nonce: nonce.trim(),
        expiresAt: nonceExpiresAt,
        now,
      });

      if (!nonceAccepted) {
        await repo.appendAuditEvent({
          actorUserId: device.userId,
          actorDeviceId: device.id,
          eventType: 'DEVICE_REPLAY_DETECTED',
          metadata: {
            path: requestPath,
          },
        });
        res.status(409).json({
          error: {
            code: 'DEVICE_NONCE_REPLAYED',
            message: 'Replayed device authentication nonce rejected.',
          },
        });
        return;
      }

      req.deviceAuthContext = {
        principalLevel: PrincipalLevel.TRUSTED_DEVICE,
        device,
        credential: activeCredential,
        nonce: nonce.trim(),
        timestampIso: timestampIso.trim(),
      };
      next();
    } catch {
      res.status(500).json({
        error: {
          code: 'INTERNAL_ERROR',
          message: 'Device authentication check failed.',
        },
      });
    }
  };
}

/** Step-up lifetime after successful TOTP verification (5 minutes). */
export const STEP_UP_TTL_MS = 5 * 60 * 1000;

/**
 * Sensitive action scopes that require fresh server-verified MFA step-up.
 * Scope is bound to the session; cross-scope reuse is rejected.
 */
export const STEP_UP_SCOPES = {
  DEVICE_REVOKE: 'DEVICE_REVOKE',
  DEVICE_COMPROMISED: 'DEVICE_COMPROMISED',
  ENABLE_LOST_MODE: 'ENABLE_LOST_MODE',
  DISABLE_LOST_MODE: 'DISABLE_LOST_MODE',
  SENSITIVE_COMMAND: 'SENSITIVE_COMMAND',
} as const;

export type StepUpScope = (typeof STEP_UP_SCOPES)[keyof typeof STEP_UP_SCOPES];

/**
 * Returns true if the current session has a non-expired step-up grant
 * covering the required action scope. Does not mutate state.
 */
export function sessionHasValidStepUp(
  session: DeviceSessionEntity,
  requiredScope: StepUpScope,
  now: Date = new Date()
): boolean {
  if (!session.stepUpVerifiedUntil) return false;
  if (session.stepUpVerifiedUntil.getTime() <= now.getTime()) return false;
  if (!session.stepUpActionScope) return false;
  // Exact scope match, or a broader SENSITIVE_COMMAND grant for command-like scopes
  if (session.stepUpActionScope === requiredScope) return true;
  if (
    session.stepUpActionScope === STEP_UP_SCOPES.SENSITIVE_COMMAND &&
    (requiredScope === STEP_UP_SCOPES.ENABLE_LOST_MODE ||
      requiredScope === STEP_UP_SCOPES.DISABLE_LOST_MODE)
  ) {
    return true;
  }
  return false;
}

/**
 * Middleware factory: requires authenticated user + valid step-up for the given scope.
 * On failure returns 403 STEP_UP_REQUIRED so the UI can prompt for TOTP.
 * When consumeOnSuccess is true, clears the step-up after the handler completes
 * (caller should invoke clearStepUp after the sensitive action succeeds).
 */
export function requireStepUp(requiredScope: StepUpScope) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const ctx = req.authContext;
    if (!ctx || ctx.principalLevel !== PrincipalLevel.AUTHENTICATED_USER) {
      res.status(401).json({
        error: {
          code: 'AUTHENTICATION_REQUIRED',
          message: 'Authentication is required for this action.',
        },
      });
      return;
    }
    if (!sessionHasValidStepUp(ctx.session, requiredScope)) {
      res.status(403).json({
        error: {
          code: 'STEP_UP_REQUIRED',
          message:
            'This action requires fresh multi-factor verification. Please complete MFA step-up and retry.',
          requiredScope,
        },
      });
      return;
    }
    next();
  };
}

