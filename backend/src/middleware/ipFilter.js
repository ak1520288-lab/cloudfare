const { isIP } = require('node:net');
const { recordEvent } = require('../../database/services/eventService');

function normalizeIP(value) {
  if (typeof value !== 'string') return null;
  const ip = value.trim().replace(/^::ffff:/i, '');
  return isIP(ip) ? ip : null;
}

function resolveClientIP(req, res, next) {
  const clientIP = normalizeIP(req.ip) || normalizeIP(req.socket.remoteAddress);

  if (!clientIP) {
    return res.status(400).json({ error: 'Unable to determine a valid client IP address.' });
  }

  req.clientIP = clientIP;
  return next();
}

function createIpFilter({ redisClient }) {
  return async function ipFilter(req, res, next) {
    const clientIP = normalizeIP(req.clientIP);

    if (!clientIP) {
      return res.status(400).json({ error: 'Unable to determine a valid client IP address.' });
    }

    try {
      const reason = await redisClient.get(`blocked:${clientIP}`);
      if (reason) {
        await recordEvent({
          category: 'ip_block',
          outcome: 'blocked',
          method: req.method,
          path: req.originalUrl,
          ip: clientIP,
          statusCode: 403,
          reason,
          requestId: req.requestId,
        });

        return res.status(403).json({
          error: 'Access denied.',
          message: 'This IP address is temporarily blocked.',
          requestId: req.requestId,
        });
      }

      next();
    } catch (error) {
      next(error);
    }
  };
}

module.exports = { createIpFilter, normalizeIP, resolveClientIP };
