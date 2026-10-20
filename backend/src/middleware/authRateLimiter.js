const { incrementRequestCount } = require('../../database/services/redisService');
const { recordEvent } = require('../../database/services/eventService');

function authRateLimiter(
  config,
  { increment = incrementRequestCount, record = recordEvent } = {},
) {
  return async function limitLoginAttempts(req, res, next) {
    try {
      const count = await increment(`auth:${req.clientIP}`, config.authRateWindowSeconds);
      res.setHeader('RateLimit-Limit', config.authRateLimit);
      res.setHeader('RateLimit-Remaining', Math.max(0, config.authRateLimit - count));

      if (count > config.authRateLimit) {
        await record({
          category: 'auth',
          outcome: 'blocked',
          method: req.method,
          path: req.path,
          ip: req.clientIP,
          statusCode: 429,
          reason: 'login_rate_limit_exceeded',
          requestId: req.requestId,
        });
        res.setHeader('Retry-After', config.authRateWindowSeconds);
        return res.status(429).json({ error: 'Too many login attempts. Try again later.' });
      }

      next();
    } catch (error) {
      next(error);
    }
  };
}

module.exports = authRateLimiter;
