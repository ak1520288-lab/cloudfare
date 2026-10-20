const { incrementRequestCount, blockIP } = require('../../database/services/redisService');
const { recordEvent } = require('../../database/services/eventService');

function createRateLimiter(config) {
  return async function rateLimiter(req, res, next) {
    try {
      const currentCount = await incrementRequestCount(
        req.clientIP,
        config.proxyRateWindowSeconds,
      );

      res.setHeader('RateLimit-Limit', config.proxyRateLimit);
      res.setHeader('RateLimit-Remaining', Math.max(0, config.proxyRateLimit - currentCount));
      res.setHeader('RateLimit-Policy', `${config.proxyRateLimit};w=${config.proxyRateWindowSeconds}`);

      if (currentCount > config.proxyRateLimit) {
        await blockIP(req.clientIP, config.proxyBlockSeconds, 'rate_limit_exceeded');
        await recordEvent({
          category: 'rate_limit',
          outcome: 'blocked',
          method: req.method,
          path: req.originalUrl,
          ip: req.clientIP,
          statusCode: 429,
          reason: `over_${config.proxyRateLimit}_requests_in_${config.proxyRateWindowSeconds}s`,
          requestId: req.requestId,
        });

        return res.status(429).json({
          error: 'Too many requests.',
          message: `The limit is ${config.proxyRateLimit} requests per ${config.proxyRateWindowSeconds} seconds. This IP is blocked temporarily.`,
          requestId: req.requestId,
        });
      }

      next();
    } catch (error) {
      next(error);
    }
  };
}

module.exports = { createRateLimiter };
