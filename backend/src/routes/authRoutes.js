const express = require('express');
const { createSession, deleteSession } = require('../../database/services/sessionService');
const { hashPassword, verifyPassword } = require('../services/passwordService');
const User = require('../../database/models/User');
const { recordEvent } = require('../../database/services/eventService');
const { incrementRequestCount } = require('../../database/services/redisService');
const { readCookie, requireAuth, requireCsrf } = require('../middleware/apiAuth');
const authRateLimiter = require('../middleware/authRateLimiter');

function asyncRoute(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

function buildAuthRouter({
  config,
  redisClient,
  record = recordEvent,
  verify = verifyPassword,
  hash = hashPassword,
  increment = incrementRequestCount,
  UserModel = User,
}) {
  const router = express.Router();
  const authenticate = requireAuth(redisClient, config);

  router.post(
    '/signup',
    authRateLimiter(config, { increment, record }),
    asyncRoute(async (req, res) => {
      const username =
        typeof req.body?.username === 'string' ? req.body.username.trim().toLowerCase() : '';
      const password = req.body?.password;
      if (
        !/^[a-z0-9][a-z0-9_.-]{2,63}$/.test(username) ||
        typeof password !== 'string' ||
        password.length < 12 ||
        password.length > 1024
      ) {
        return res.status(400).json({
          error: 'Choose a username (3-64 letters, numbers, dots, underscores, or hyphens) and a password of at least 12 characters.',
        });
      }

      if (username === config.adminUsername || await UserModel.findOne({ username })) {
        await record({
          category: 'auth',
          outcome: 'blocked',
          method: req.method,
          path: req.path,
          ip: req.clientIP,
          statusCode: 409,
          reason: 'signup_username_unavailable',
          actor: username,
          requestId: req.requestId,
        });
        return res.status(409).json({ error: 'That username is unavailable.' });
      }

      const passwordParts = await hash(password);
      let account;
      try {
        account = await UserModel.create({
          username,
          passwordSalt: passwordParts.salt,
          passwordHash: passwordParts.hash,
          role: 'viewer',
        });
      } catch (error) {
        if (error.code !== 11000) throw error;
        await record({
          category: 'auth',
          outcome: 'blocked',
          method: req.method,
          path: req.path,
          ip: req.clientIP,
          statusCode: 409,
          reason: 'signup_username_unavailable',
          actor: username,
          requestId: req.requestId,
        });
        return res.status(409).json({ error: 'That username is unavailable.' });
      }

      const { token, session } = await createSession(
        redisClient,
        config,
        account.username,
        account.role,
      );
      try {
        await record({
          category: 'auth',
          outcome: 'allowed',
          method: req.method,
          path: req.path,
          ip: req.clientIP,
          statusCode: 201,
          reason: 'account_registered',
          actor: account.username,
          requestId: req.requestId,
        });
      } catch (error) {
        await deleteSession(redisClient, config, token);
        console.error(`Account ${account.username} was created but its signup audit record failed:`, error);
        return res.status(503).json({
          error: 'The account was created, but its audit record could not be saved. Sign in to continue.',
          requestId: req.requestId,
        });
      }
      const cookie = [
        `anti_session=${encodeURIComponent(token)}`,
        'Path=/api',
        'HttpOnly',
        'SameSite=Strict',
        `Max-Age=${config.sessionTtlSeconds}`,
      ];
      if (config.cookieSecure) cookie.push('Secure');
      res.setHeader('Set-Cookie', cookie.join('; '));
      return res.status(201).json({
        user: { username: session.username, role: session.role },
        csrfToken: session.csrfToken,
        expiresIn: config.sessionTtlSeconds,
      });
    }),
  );

  router.post(
    '/login',
    authRateLimiter(config, { increment, record }),
    asyncRoute(async (req, res) => {
      const { username, password } = req.body || {};
      if (
        typeof username !== 'string' ||
        username.trim().length < 1 ||
        username.trim().length > 64 ||
        typeof password !== 'string' ||
        password.length < 1 ||
        password.length > 1024
      ) {
        return res.status(400).json({ error: 'A valid username and password are required.' });
      }

      const normalizedUsername = username.trim().toLowerCase();
      const isConfiguredAdmin = normalizedUsername === config.adminUsername;
      const account = isConfiguredAdmin
        ? null
        : await UserModel.findOne({ username: normalizedUsername })
          .select('+passwordSalt +passwordHash');
      const passwordMatches = isConfiguredAdmin
        ? await verify(password, config.adminPasswordSalt, config.adminPasswordHash)
        : account
          ? await verify(password, account.passwordSalt, account.passwordHash)
          : false;

      if (!passwordMatches) {
        await record({
          category: 'auth',
          outcome: 'blocked',
          method: req.method,
          path: req.path,
          ip: req.clientIP,
          statusCode: 401,
          reason: 'invalid_credentials',
          actor: normalizedUsername,
          requestId: req.requestId,
        });
        return res.status(401).json({ error: 'Invalid username or password.' });
      }

      const { token, session } = await createSession(
        redisClient,
        config,
        isConfiguredAdmin ? config.adminUsername : account.username,
        isConfiguredAdmin ? 'admin' : account.role,
      );

      try {
        await record({
          category: 'auth',
          outcome: 'allowed',
          method: req.method,
          path: req.path,
          ip: req.clientIP,
          statusCode: 200,
          reason: 'login_success',
          actor: session.username,
          requestId: req.requestId,
        });
      } catch (error) {
        try {
          await deleteSession(redisClient, config, token);
        } catch (cleanupError) {
          throw new AggregateError(
            [error, cleanupError],
            'Login audit persistence failed and the new session could not be revoked.',
          );
        }
        throw error;
      }
      const cookie = [
        `anti_session=${encodeURIComponent(token)}`,
        'Path=/api',
        'HttpOnly',
        'SameSite=Strict',
        `Max-Age=${config.sessionTtlSeconds}`,
      ];
      if (config.cookieSecure) cookie.push('Secure');
      res.setHeader('Set-Cookie', cookie.join('; '));

      return res.json({
        user: { username: session.username, role: session.role },
        csrfToken: session.csrfToken,
        expiresIn: config.sessionTtlSeconds,
      });
    }),
  );

  router.get('/session', authenticate, (req, res) => {
    res.json({
      user: { username: req.adminSession.username, role: req.adminSession.role },
      csrfToken: req.adminSession.csrfToken,
    });
  });

  router.delete(
    '/session',
    authenticate,
    requireCsrf,
    asyncRoute(async (req, res) => {
      await deleteSession(redisClient, config, readCookie(req, 'anti_session'));
      res.setHeader('Set-Cookie', [
        'anti_session=',
        'Path=/api',
        'HttpOnly',
        'SameSite=Strict',
        'Max-Age=0',
        ...(config.cookieSecure ? ['Secure'] : []),
      ].join('; '));
      await record({
        category: 'auth',
        outcome: 'allowed',
        method: req.method,
        path: req.path,
        ip: req.clientIP,
        statusCode: 200,
        reason: 'logout',
        actor: req.adminSession.username,
        requestId: req.requestId,
      });
      return res.sendStatus(204);
    }),
  );

  return router;
}

module.exports = { buildAuthRouter };
