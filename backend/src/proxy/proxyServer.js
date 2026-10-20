// This creates the actual reverse proxy.
// Traffic that PASSES all middleware checks gets forwarded to the origin server.

const { createProxyMiddleware, fixRequestBody } = require('http-proxy-middleware');

const ORIGIN_SERVER = process.env.ORIGIN_SERVER || 'http://localhost:4000';

const proxy = createProxyMiddleware({
  target: ORIGIN_SERVER,
  changeOrigin: true,
  xfwd: false,
  onProxyReq: (proxyReq, req) => {
    fixRequestBody(proxyReq, req);

    // Do not trust a client-supplied X-Forwarded-For value.
    proxyReq.setHeader('X-Forwarded-For', req.clientIP);
  },
  onError: (err, req, res) => {
    console.error('Proxy error:', err.message);
    res.status(502).json({ error: 'Bad Gateway', message: 'Origin server unreachable.' });
  }
});

module.exports = proxy;
