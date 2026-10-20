const { recordEvent } = require('../../database/services/eventService');

function logger(req, res, next) {
  const startedAt = Date.now();

  res.once('finish', () => {
    const durationMs = Date.now() - startedAt;
    const outcome = res.statusCode < 400 ? 'allowed' : 'warning';
    const event = {
      category: 'proxy',
      outcome,
      method: req.method,
      path: req.originalUrl,
      ip: req.clientIP,
      statusCode: res.statusCode,
      requestId: req.requestId,
      durationMs,
    };

    console.info(JSON.stringify({
      time: new Date().toISOString(),
      requestId: req.requestId,
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      durationMs,
    }));

    recordEvent(event).catch((error) => {
      console.error(`Failed to persist request ${req.requestId}:`, error);
    });
  });

  next();
}

module.exports = logger;
