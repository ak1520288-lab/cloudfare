const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const express = require('express');
const { hashSessionToken, readConfig } = require('../src/config');
const { normalizeIP, resolveClientIP } = require('../src/middleware/ipFilter');
const { inspectPayload } = require('../src/middleware/wafRules');
const { hashPassword, verifyPassword } = require('../src/services/passwordService');
const { createSession, deleteSession, getSession } = require('../database/services/sessionService');
const { validPublicSiteUrl } = require('../src/routes/dashboardRoutes');

const scrypt = promisify(crypto.scrypt);

function validEnvironment(overrides = {}) {
  return {
    ADMIN_USERNAME: 'Admin',
    ADMIN_PASSWORD_HASH: `scrypt$${'a'.repeat(32)}$${'b'.repeat(128)}`,
    SESSION_SECRET: 'session-secret-for-test-only'.padEnd(48, 'x'),
    ...overrides,
  };
}

test('configuration validates credentials, secrets and origin settings', () => {
  const config = readConfig(validEnvironment());
  assert.equal(config.adminUsername, 'admin');
  assert.equal(config.port, 8080);
  assert.equal(config.proxyRateLimit, 30);
  assert.throws(
    () => readConfig(validEnvironment({ SESSION_SECRET: 'short' })),
    /at least 32 bytes/,
  );
  assert.throws(
    () => readConfig(validEnvironment({ ORIGIN_SERVER: 'file:///etc/passwd' })),
    /HTTP or HTTPS/,
  );
  assert.throws(
    () => readConfig(validEnvironment({ TRUST_PROXY_HOPS: '11' })),
    /TRUST_PROXY_HOPS/,
  );
});

test('session keys are opaque HMACs and sessions expire from Redis storage', async () => {
  const values = new Map();
  const redis = {
    async set(key, value, options) {
      assert.equal(options.EX, 600);
      values.set(key, value);
    },
    async get(key) {
      return values.get(key) || null;
    },
    async del(key) {
      return values.delete(key) ? 1 : 0;
    },
  };
  const config = readConfig(validEnvironment({ SESSION_TTL_SECONDS: '600' }));
  const { token, session } = await createSession(redis, config, 'admin');

  assert.equal(token.length > 32, true);
  assert.equal([...values.keys()][0], `session:${hashSessionToken(token, config.sessionSecret)}`);
  assert.equal(JSON.stringify([...values.values()]).includes(token), false);
  assert.deepEqual(await getSession(redis, config, token), session);
  await deleteSession(redis, config, token);
  assert.equal(await getSession(redis, config, token), null);
});

test('password verification uses the configured scrypt hash', async () => {
  const password = 'Correct horse battery staple!';
  const salt = crypto.randomBytes(16);
  const derived = await scrypt(password, salt, 64, {
    N: 32768,
    r: 8,
    p: 1,
    maxmem: 64 * 1024 * 1024,
  });

  assert.equal(
    await verifyPassword(password, salt.toString('hex'), derived.toString('hex')),
    true,
  );
  assert.equal(
    await verifyPassword('incorrect password', salt.toString('hex'), derived.toString('hex')),
    false,
  );
  const stored = await hashPassword(password);
  assert.equal(await verifyPassword(password, stored.salt, stored.hash), true);
});

test('WAF identifies encoded and nested attack patterns without flagging normal paths', () => {
  assert.equal(inspectPayload('/search?q=hello-world'), null);
  assert.equal(inspectPayload('/search?q=%3Cscript%3Ealert(1)%3C/script%3E'), 'cross_site_scripting');
  assert.equal(inspectPayload({ filter: "' OR 1=1 --" }), 'sql_injection');
  assert.equal(inspectPayload('/files/..%2f..%2fsecret.txt'), 'path_traversal');
});

test('client IP is resolved dynamically through the configured trusted proxy', async (t) => {
  const app = express();
  app.set('trust proxy', 1);
  app.use(resolveClientIP);
  app.get('/ip', (req, res) => res.json({ ip: req.clientIP }));

  const server = await new Promise((resolve) => {
    const listeningServer = app.listen(0, '127.0.0.1', () => resolve(listeningServer));
  });
  t.after(() => new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  }));

  const url = `http://127.0.0.1:${server.address().port}/ip`;
  const first = await fetch(url, { headers: { 'X-Forwarded-For': '198.51.100.20' } });
  const second = await fetch(url, { headers: { 'X-Forwarded-For': '198.51.100.21' } });
  assert.deepEqual(await first.json(), { ip: '198.51.100.20' });
  assert.deepEqual(await second.json(), { ip: '198.51.100.21' });
});

test('client IP and simulation URL validation reject malformed input', () => {
  assert.equal(normalizeIP('::ffff:127.0.0.1'), '127.0.0.1');
  assert.equal(normalizeIP('2001:db8::1'), '2001:db8::1');
  assert.equal(normalizeIP('not-an-ip'), null);
  assert.equal(validPublicSiteUrl('https://example.com/safe').hostname, 'example.com');
  assert.equal(validPublicSiteUrl('javascript:alert(1)'), null);
  assert.equal(validPublicSiteUrl('https://user:password@example.com'), null);
});
