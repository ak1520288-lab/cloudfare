function apiSecurity(config) {
  return function setApiSecurityHeaders(req, res, next) {
    if (!req.path.startsWith('/api')) return next();

    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-site');

    const origin = req.get('Origin');
    if (origin) {
      if (!config.allowedOrigins.includes(origin)) {
        return res.status(403).json({ error: 'Origin is not allowed.' });
      }

      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Vary', 'Origin');
    }

    if (req.method === 'OPTIONS') {
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-CSRF-Token');
      res.setHeader('Access-Control-Max-Age', '600');
      return res.sendStatus(204);
    }

    next();
  };
}

module.exports = apiSecurity;
