const crypto = require('node:crypto');
const { getSession } = require('../../database/services/sessionService');

function readCookie(req, name) {
  const cookieHeader = req.headers.cookie || '';
  for (const pair of cookieHeader.split(';')) {
    const separator = pair.indexOf('=');
    if (separator < 0) continue;

    const key = pair.slice(0, separator).trim();
    if (key !== name) continue;

    const value = pair.slice(separator + 1).trim();
    try {
      return decodeURIComponent(value);
    } catch {
      return null;
    }
  }
  return null;
}

function requireAuth(redisClient, config) {
  return async function authenticateAdmin(req, res, next) {
    try {
      const token = readCookie(req, 'anti_session');
      const session = await getSession(redisClient, config, token);

      if (!session) {
        return res.status(401).json({ error: 'Authentication required.' });
      }

      req.sessionToken = token;
      req.adminSession = session;
      next();
    } catch (error) {
      next(error);
    }
  };
}

function requireCsrf(req, res, next) {
  const submittedToken = req.get('X-CSRF-Token');
  const expected = req.adminSession?.csrfToken;

  if (
    typeof submittedToken !== 'string' ||
    typeof expected !== 'string' ||
    Buffer.byteLength(submittedToken) !== Buffer.byteLength(expected) ||
    !crypto.timingSafeEqual(
      Buffer.from(submittedToken),
      Buffer.from(expected),
    )
  ) {
    return res.status(403).json({ error: 'CSRF token is missing or invalid.' });
  }

  next();
}

function requireAdmin(req, res, next) {
  if (req.adminSession?.role !== 'admin') {
    return res.status(403).json({ error: 'Administrator access is required.' });
  }
  next();
}

module.exports = { readCookie, requireAuth, requireCsrf, requireAdmin };
