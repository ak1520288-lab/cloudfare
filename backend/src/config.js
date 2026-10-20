const crypto = require('node:crypto');

function positiveInteger(value, fallback, name) {
  const parsed = Number(value ?? fallback);
  if (!Number.isInteger(parsed) || parsed < 1) {
    throw new Error(`${name} must be a positive integer.`);
  }
  return parsed;
}

function readConfig(env = process.env) {
  const adminUsername = String(env.ADMIN_USERNAME || '').trim();
  const passwordParts = String(env.ADMIN_PASSWORD_HASH || '').split('$');
  const sessionSecret = String(env.SESSION_SECRET || '');

  if (!adminUsername || adminUsername.length > 64) {
    throw new Error('Set ADMIN_USERNAME to a non-empty value of at most 64 characters.');
  }

  if (
    passwordParts.length !== 3 ||
    passwordParts[0] !== 'scrypt' ||
    !/^[a-f\d]{32}$/i.test(passwordParts[1]) ||
    !/^[a-f\d]{128}$/i.test(passwordParts[2])
  ) {
    throw new Error(
      'ADMIN_PASSWORD_HASH is invalid. Generate it with "npm run create-admin-hash".',
    );
  }

  if (Buffer.byteLength(sessionSecret, 'utf8') < 32) {
    throw new Error('SESSION_SECRET must contain at least 32 bytes.');
  }

  const allowedOrigins = String(
    env.CORS_ORIGINS || 'http://localhost:5173,http://127.0.0.1:5173',
  )
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);

  for (const origin of allowedOrigins) {
    let parsed;
    try {
      parsed = new URL(origin);
    } catch {
      throw new Error(`Invalid origin in CORS_ORIGINS: ${origin}`);
    }

    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.origin !== origin) {
      throw new Error(`CORS_ORIGINS entries must be HTTP(S) origins without paths: ${origin}`);
    }
  }

  const trustProxyHops = Number(env.TRUST_PROXY_HOPS || 0);
  if (!Number.isInteger(trustProxyHops) || trustProxyHops < 0 || trustProxyHops > 10) {
    throw new Error('TRUST_PROXY_HOPS must be an integer between 0 and 10.');
  }

  const port = positiveInteger(env.PORT, 8080, 'PORT');
  if (port > 65535) throw new Error('PORT must not exceed 65535.');
  const originServer = env.ORIGIN_SERVER || 'http://localhost:4000';
  let parsedOrigin;
  try {
    parsedOrigin = new URL(originServer);
  } catch {
    throw new Error('ORIGIN_SERVER must be a valid HTTP or HTTPS URL.');
  }
  if (!['http:', 'https:'].includes(parsedOrigin.protocol)) {
    throw new Error('ORIGIN_SERVER must use HTTP or HTTPS.');
  }

  return Object.freeze({
    port,
    originServer,
    openRouterApiKey: String(env.OPENROUTER_API_KEY || '').trim(),
    openRouterModel: String(env.OPENROUTER_MODEL || 'openrouter/free').trim(),
    redisUrl: env.REDIS_URL || 'redis://localhost:6379',
    mongoUri: env.MONGODB_URI || 'mongodb://127.0.0.1:27017/anti_cloudflare',
    adminUsername: adminUsername.toLowerCase(),
    adminPasswordSalt: passwordParts[1],
    adminPasswordHash: passwordParts[2],
    sessionSecret,
    sessionTtlSeconds: positiveInteger(env.SESSION_TTL_SECONDS, 28800, 'SESSION_TTL_SECONDS'),
    authRateLimit: positiveInteger(env.AUTH_RATE_LIMIT, 10, 'AUTH_RATE_LIMIT'),
    authRateWindowSeconds: positiveInteger(
      env.AUTH_RATE_WINDOW_SECONDS,
      900,
      'AUTH_RATE_WINDOW_SECONDS',
    ),
    proxyRateLimit: positiveInteger(env.PROXY_RATE_LIMIT, 30, 'PROXY_RATE_LIMIT'),
    proxyRateWindowSeconds: positiveInteger(
      env.PROXY_RATE_WINDOW_SECONDS,
      60,
      'PROXY_RATE_WINDOW_SECONDS',
    ),
    proxyBlockSeconds: positiveInteger(env.PROXY_BLOCK_SECONDS, 300, 'PROXY_BLOCK_SECONDS'),
    eventRetentionDays: positiveInteger(env.EVENT_RETENTION_DAYS, 30, 'EVENT_RETENTION_DAYS'),
    cookieSecure: env.COOKIE_SECURE === 'true' || env.NODE_ENV === 'production',
    allowedOrigins,
    trustProxyHops,
  });
}

function hashSessionToken(token, secret) {
  return crypto.createHmac('sha256', secret).update(token).digest('hex');
}

module.exports = { readConfig, hashSessionToken };
