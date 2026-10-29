/**
 * VAJRA Full-Stack Server Entry Point
 * Prompt 0003 / 0013: PostgreSQL via Prisma in production (fail closed);
 * in-memory repository only for local development / tests when DB is unset.
 */

import path from 'path';
import { fileURLToPath } from 'url';
import http from 'http';
import express from 'express';
import { PrismaClient } from '@prisma/client';
import { createServer as createViteServer } from 'vite';
import { createVajraApiApp } from './src/server/app.ts';
import {
  IdentityRepository,
  PrismaIdentityRepository,
  InMemoryIdentityRepository,
} from './src/server/db/repository.ts';
import {
  assertProductionConfigOrThrow,
  validateRuntimeConfig,
} from './packages/config/src/index.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function isProductionEnv(): boolean {
  const nodeEnv = process.env.NODE_ENV?.trim().toLowerCase();
  const appEnv = process.env.APP_ENV?.trim().toLowerCase();
  return nodeEnv === 'production' || appEnv === 'production';
}

function isPlaceholderDatabaseUrl(dbUrl: string): boolean {
  const u = dbUrl.trim().toLowerCase();
  if (!u) return true;
  return (
    u.includes('username:password@') ||
    u.includes('user:password@') ||
    u.includes('localhost:5432/vajra_db') ||
    u.includes('example.com') ||
    u.includes('changeme')
  );
}

async function resolveIdentityRepository(): Promise<{
  repository: IdentityRepository;
  prisma: PrismaClient | null;
}> {
  const dbUrl = process.env.DATABASE_URL?.trim() ?? '';
  const production = isProductionEnv();
  const looksPostgres =
    dbUrl.startsWith('postgresql://') || dbUrl.startsWith('postgres://');
  const placeholder = isPlaceholderDatabaseUrl(dbUrl);

  if (production) {
    if (!looksPostgres || placeholder) {
      throw new Error(
        '[VAJRA] Production requires a non-placeholder DATABASE_URL (PostgreSQL). In-memory fallback is disabled.'
      );
    }
    const prisma = new PrismaClient();
    try {
      await prisma.$connect();
    } catch {
      throw new Error(
        '[VAJRA] PostgreSQL is unreachable at startup. Production refuses to start without a healthy database.'
      );
    }
    return { repository: new PrismaIdentityRepository(prisma), prisma };
  }

  // Development / test: prefer PostgreSQL when configured; otherwise in-memory.
  if (looksPostgres && !placeholder) {
    try {
      const prisma = new PrismaClient();
      await prisma.$connect();
      return { repository: new PrismaIdentityRepository(prisma), prisma };
    } catch {
      console.warn(
        '[VAJRA] PostgreSQL connection unreachable in non-production; using in-memory repository.'
      );
      return { repository: new InMemoryIdentityRepository(), prisma: null };
    }
  }

  return { repository: new InMemoryIdentityRepository(), prisma: null };
}

async function startServer(): Promise<void> {
  const production = isProductionEnv();
  if (production) {
    assertProductionConfigOrThrow(process.env);
  }

  const { config, valid, errors } = validateRuntimeConfig(process.env);
  if (production && !valid) {
    throw new Error(`[VAJRA] Production configuration invalid: ${errors.join(' ')}`);
  }

  const { repository, prisma } = await resolveIdentityRepository();
  const app = createVajraApiApp({
    repository,
    totpEncryptionKey: process.env.TOTP_ENCRYPTION_KEY,
  });

  if (config.trustProxy) {
    app.set('trust proxy', 1);
  }

  const PORT = config.port;

  // Production: serve Vite build; never let SPA fallback capture /api/*
  if (production || config.nodeEnv === 'production') {
    const distPath = path.join(__dirname, 'dist');
    app.use(express.static(distPath, { index: false, maxAge: '1h' }));
    app.get('*', (req, res, next) => {
      if (req.path.startsWith('/api')) {
        next();
        return;
      }
      res.sendFile(path.join(distPath, 'index.html'), (err) => {
        if (err) next(err);
      });
    });
  } else {
    // Development: Vite middleware mode (HMR disabled for agent stability)
    let viteMiddleware: express.RequestHandler | null = null;
    app.use((req, res, next) => {
      if (viteMiddleware) {
        viteMiddleware(req, res, next);
      } else {
        next();
      }
    });
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        hmr: false,
        watch: null,
      },
      appType: 'spa',
    });
    viteMiddleware = vite.middlewares;
  }

  const server = http.createServer(app);

  const shutdown = async (signal: string) => {
    console.log(`[VAJRA] Received ${signal}; shutting down gracefully…`);
    server.close(async () => {
      try {
        if (prisma) {
          await prisma.$disconnect();
        }
      } catch {
        // ignore disconnect errors during shutdown
      }
      console.log('[VAJRA] Shutdown complete.');
      process.exit(0);
    });
    // Force exit if connections hang
    setTimeout(() => process.exit(1), 10_000).unref();
  };

  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));

  await new Promise<void>((resolve, reject) => {
    server.listen(PORT, '0.0.0.0', () => {
      console.log(
        `[VAJRA] Server listening on http://0.0.0.0:${PORT} (env=${config.nodeEnv}, identity=${repository.backendType})`
      );
      resolve();
    });
    server.on('error', reject);
  });
}

startServer().catch((err) => {
  const message = err instanceof Error ? err.message : 'Unknown error';
  // Never log full env or connection strings
  console.error('[VAJRA] Failed to start server:', message);
  process.exit(1);
});
