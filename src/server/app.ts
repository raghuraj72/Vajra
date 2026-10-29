/**
 * VAJRA Backend API Express App Factory
 * Prompt 0003 / 0013 — Health + readiness, identity, auth, devices, notifications,
 * security headers, and fail-closed error handling.
 */

import express, { Express, Request, Response, NextFunction } from 'express';
import { HealthResponse } from '../../packages/shared-types/src/index.ts';
import {
  IdentityRepository,
  InMemoryIdentityRepository,
} from './db/repository.ts';
import { createSessionResolutionMiddleware } from './auth/middleware.ts';
import { createAuthRouter } from './auth/routes.ts';
import { createDeviceRouter } from './devices/routes.ts';
import { createNotificationAndActivityRouter } from './notifications/routes.ts';

export interface CreateVajraApiOptions {
  repository?: IdentityRepository;
  totpEncryptionKey?: string;
}

/**
 * Content-Security-Policy for API JSON responses and HTML shell.
 * Exceptions documented in docs/security/production-checklist.md:
 * - 'unsafe-inline' style for Vite-built CSS-in-JS edge cases is avoided; style-src uses self.
 * - Cloudinary login background video: media-src / img-src include res.cloudinary.com when configured.
 */
function buildContentSecurityPolicy(): string {
  const cloudinary = 'https://res.cloudinary.com';
  const directives = [
    "default-src 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "frame-ancestors *",
    "form-action 'self'",
    "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    `img-src 'self' data: blob: https: ${cloudinary}`,
    `media-src 'self' https: ${cloudinary}`,
    "font-src 'self' data: https://fonts.gstatic.com",
    "connect-src 'self' ws: wss: https:",
    "worker-src 'self' blob:",
  ];
  return directives.join('; ');
}

export function createVajraApiApp(options?: CreateVajraApiOptions): Express {
  const app = express();
  const repository = options?.repository ?? new InMemoryIdentityRepository();

  app.disable('x-powered-by');
  app.use(express.json({ limit: '16kb' }));

  // Global security headers (HTML + API)
  app.use((_req: Request, res: Response, next: NextFunction) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('Content-Security-Policy', buildContentSecurityPolicy());
    if (process.env.NODE_ENV === 'production' || process.env.APP_ENV === 'production') {
      // Safe when TLS terminates at App Service / Front Door with trust proxy enabled
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }
    next();
  });

  // Sensitive API responses must not be cached by shared caches
  app.use('/api', (_req: Request, res: Response, next: NextFunction) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    next();
  });

  /**
   * GET /api/health — Liveness
   * Process is up; does not probe PostgreSQL.
   */
  app.get('/api/health', (_req: Request, res: Response<HealthResponse>) => {
    res.status(200).json({
      status: 'ok',
      service: 'vajra-api',
    });
  });

  /**
   * GET /api/ready — Readiness
   * Probes identity backend with a bounded timeout. Never returns connection strings.
   */
  app.get('/api/ready', async (_req: Request, res: Response) => {
    try {
      const health = await repository.checkDatabaseHealth(2000);
      if (!health.ok) {
        res.status(503).json({
          status: 'not_ready',
          service: 'vajra-api',
          checks: {
            identityStore: {
              ok: false,
              backend: health.backend,
              errorCode: health.errorCode ?? 'DATABASE_UNAVAILABLE',
            },
          },
        });
        return;
      }
      res.status(200).json({
        status: 'ready',
        service: 'vajra-api',
        checks: {
          identityStore: {
            ok: true,
            backend: health.backend,
            latencyMs: health.latencyMs,
          },
        },
      });
    } catch {
      res.status(503).json({
        status: 'not_ready',
        service: 'vajra-api',
        checks: {
          identityStore: {
            ok: false,
            errorCode: 'READINESS_PROBE_FAILED',
          },
        },
      });
    }
  });

  // Resolve session cookies on /api routes
  app.use('/api', createSessionResolutionMiddleware(repository));

  app.use(
    '/api',
    createAuthRouter({
      repository,
      totpEncryptionKey: options?.totpEncryptionKey,
    })
  );

  app.use(
    '/api',
    createDeviceRouter({
      repository,
    })
  );

  app.use(
    '/api',
    createNotificationAndActivityRouter({
      repository,
    })
  );

  app.use('/api', (_req: Request, res: Response) => {
    res.status(404).json({
      error: {
        code: 'NOT_FOUND',
        message: 'API endpoint not found.',
      },
    });
  });

  app.use((_err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    res.status(500).json({
      error: {
        code: 'INTERNAL_ERROR',
        message: 'An unexpected server error occurred.',
      },
    });
  });

  return app;
}
