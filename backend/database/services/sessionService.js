const crypto = require('node:crypto');
const { hashSessionToken } = require('../../src/config');

const SESSION_PREFIX = 'session:';

function sessionKey(token, secret) {
  return `${SESSION_PREFIX}${hashSessionToken(token, secret)}`;
}

async function createSession(redisClient, config, username, role = 'admin') {
  const token = crypto.randomBytes(32).toString('base64url');
  const csrfToken = crypto.randomBytes(32).toString('base64url');
  const session = {
    username,
    role,
    csrfToken,
    createdAt: new Date().toISOString(),
  };

  await redisClient.set(sessionKey(token, config.sessionSecret), JSON.stringify(session), {
    EX: config.sessionTtlSeconds,
  });

  return { token, session };
}

async function getSession(redisClient, config, token) {
  if (!token) return null;
  const value = await redisClient.get(sessionKey(token, config.sessionSecret));
  if (!value) return null;

  try {
    const session = JSON.parse(value);
    if (typeof session.username !== 'string' || typeof session.csrfToken !== 'string') {
      throw new Error('Invalid session shape');
    }
    if (!['admin', 'viewer'].includes(session.role)) {
      session.role = session.username === config.adminUsername ? 'admin' : 'viewer';
    }
    return session;
  } catch (error) {
    await redisClient.del(sessionKey(token, config.sessionSecret));
    console.error('Removed malformed session record:', error.message);
    return null;
  }
}

async function deleteSession(redisClient, config, token) {
  if (!token) return;
  await redisClient.del(sessionKey(token, config.sessionSecret));
}

module.exports = { createSession, getSession, deleteSession };
