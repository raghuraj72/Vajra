/**
 * @vajra/config
 * Environment configuration validation and safe runtime defaults.
 * Prompt 0003 / 0013: Validates APP_ENV, DATABASE_URL, SESSION_SECRET, and TOTP_ENCRYPTION_KEY
 * without exposing secret values in logs or public endpoints.
 */

export interface VajraRuntimeConfig {
  readonly appEnv: 'development' | 'production' | 'test';
  readonly nodeEnv: 'development' | 'production' | 'test';
  readonly port: number;
  readonly serviceName: 'vajra-api';
  readonly sessionTtlSeconds: number;
  readonly requireMfa: boolean;
  readonly databaseConfigured: boolean;
  readonly publicOrigin: string | null;
  readonly trustProxy: boolean;
}

export interface ConfigValidationResult {
  readonly valid: boolean;
  readonly errors: string[];
  readonly config: VajraRuntimeConfig;
}

const DEFAULT_CONFIG: VajraRuntimeConfig = {
  appEnv: 'development',
  nodeEnv: 'development',
  port: 3000,
  serviceName: 'vajra-api',
  sessionTtlSeconds: 900,
  requireMfa: true,
  databaseConfigured: false,
  publicOrigin: null,
  trustProxy: false,
};

const PLACEHOLDER_SECRET_PATTERNS = [
  /^change.?me/i,
  /^replace.?me/i,
  /^your[_-]?secret/i,
  /^todo/i,
  /^xxx+$/i,
  /^test[_-]?secret/i,
  /^password$/i,
  /^secret$/i,
];

function looksLikePlaceholderSecret(value: string): boolean {
  const v = value.trim();
  if (v.length < 32) return true;
  return PLACEHOLDER_SECRET_PATTERNS.some((re) => re.test(v));
}

function isPlaceholderDatabaseUrl(url: string): boolean {
  const u = url.trim().toLowerCase();
  if (!u) return true;
  return (
    u.includes('username:password@') ||
    u.includes('user:password@') ||
    u.includes('localhost:5432/vajra_db') ||
    u.includes('example.com') ||
    u.includes('changeme')
  );
}

/**
 * Validates environment input without throwing or exposing sensitive values in error outputs.
 */
export function validateRuntimeConfig(
  env: Record<string, string | undefined> = {}
): ConfigValidationResult {
  const errors: string[] = [];

  const validEnvs = ['development', 'production', 'test'] as const;

  const rawNodeEnv = env.NODE_ENV ?? DEFAULT_CONFIG.nodeEnv;
  const nodeEnv = (validEnvs.includes(rawNodeEnv as (typeof validEnvs)[number])
    ? rawNodeEnv
    : 'development') as VajraRuntimeConfig['nodeEnv'];

  if (env.NODE_ENV && !validEnvs.includes(env.NODE_ENV as (typeof validEnvs)[number])) {
    errors.push('Invalid NODE_ENV specified; must be development, production, or test.');
  }

  const rawAppEnv = env.APP_ENV ?? nodeEnv;
  const appEnv = (validEnvs.includes(rawAppEnv as (typeof validEnvs)[number])
    ? rawAppEnv
    : nodeEnv) as VajraRuntimeConfig['appEnv'];

  if (env.APP_ENV && !validEnvs.includes(env.APP_ENV as (typeof validEnvs)[number])) {
    errors.push('Invalid APP_ENV specified; must be development, production, or test.');
  }

  let port = DEFAULT_CONFIG.port;
  if (env.PORT !== undefined && env.PORT !== '') {
    const parsedPort = Number.parseInt(env.PORT, 10);
    if (Number.isNaN(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
      errors.push('Invalid PORT specified; must be an integer between 1 and 65535.');
    } else {
      port = parsedPort;
    }
  }

  let sessionTtlSeconds = DEFAULT_CONFIG.sessionTtlSeconds;
  if (env.SESSION_TTL_SECONDS !== undefined && env.SESSION_TTL_SECONDS !== '') {
    const parsedTtl = Number.parseInt(env.SESSION_TTL_SECONDS, 10);
    if (Number.isNaN(parsedTtl) || parsedTtl < 60 || parsedTtl > 86400) {
      errors.push('SESSION_TTL_SECONDS must be between 60 and 86400 seconds.');
    } else {
      sessionTtlSeconds = parsedTtl;
    }
  }

  const requireMfa = env.REQUIRE_MFA ? env.REQUIRE_MFA.toLowerCase() !== 'false' : true;

  const databaseUrl = env.DATABASE_URL?.trim() ?? '';
  const databaseConfigured =
    (databaseUrl.startsWith('postgresql://') || databaseUrl.startsWith('postgres://')) &&
    !isPlaceholderDatabaseUrl(databaseUrl);

  const publicOriginRaw = env.APP_PUBLIC_ORIGIN?.trim() || env.APP_URL?.trim() || '';
  let publicOrigin: string | null = null;
  if (publicOriginRaw && publicOriginRaw !== 'MY_APP_URL') {
    try {
      const u = new URL(publicOriginRaw);
      if (u.protocol === 'http:' || u.protocol === 'https:') {
        publicOrigin = `${u.protocol}//${u.host}`;
      } else {
        errors.push('APP_PUBLIC_ORIGIN must be an http or https URL.');
      }
    } catch {
      errors.push('APP_PUBLIC_ORIGIN must be a valid absolute URL.');
    }
  }

  const trustProxy =
    env.TRUST_PROXY === 'true' ||
    env.TRUST_PROXY === '1' ||
    appEnv === 'production';

  if (appEnv === 'production' || nodeEnv === 'production') {
    if (!databaseConfigured) {
      errors.push(
        'DATABASE_URL must be a non-placeholder PostgreSQL connection string in production.'
      );
    }
    if (!env.SESSION_SECRET || looksLikePlaceholderSecret(env.SESSION_SECRET)) {
      errors.push(
        'SESSION_SECRET must be a high-entropy secret of at least 32 characters in production (not a placeholder).'
      );
    }
    if (!env.TOTP_ENCRYPTION_KEY || looksLikePlaceholderSecret(env.TOTP_ENCRYPTION_KEY)) {
      errors.push(
        'TOTP_ENCRYPTION_KEY must be a high-entropy secret of at least 32 characters in production (not a placeholder).'
      );
    }
    if (
      env.SESSION_SECRET &&
      env.TOTP_ENCRYPTION_KEY &&
      env.SESSION_SECRET.trim() === env.TOTP_ENCRYPTION_KEY.trim()
    ) {
      errors.push('SESSION_SECRET and TOTP_ENCRYPTION_KEY must be distinct keys.');
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    config: {
      appEnv,
      nodeEnv,
      port,
      serviceName: 'vajra-api',
      sessionTtlSeconds,
      requireMfa,
      databaseConfigured,
      publicOrigin,
      trustProxy,
    },
  };
}

/**
 * Throws a secret-free Error when production configuration is invalid.
 */
export function assertProductionConfigOrThrow(
  env: Record<string, string | undefined> = process.env
): VajraRuntimeConfig {
  const result = validateRuntimeConfig(env);
  const isProd =
    result.config.appEnv === 'production' || result.config.nodeEnv === 'production';
  if (isProd && !result.valid) {
    const message = `[VAJRA] Production configuration invalid: ${result.errors.join(' ')}`;
    throw new Error(message);
  }
  return result.config;
}
