require('dotenv').config();

const { readConfig } = require('./config');
const config = readConfig();
const express = require('express');
const mongoose = require('mongoose');
const User = require('../database/models/User');
const { buildAuthRouter } = require('./routes/authRoutes');
const { buildDashboardRouter } = require('./routes/dashboardRoutes');
const { createSecurityAssistant } = require('./services/securityAssistant');
const SecurityEvent = require('../database/models/SecurityEvent');
const { redisClient, isRedisReady } = require('../database/services/redisService');
const { createIpFilter, resolveClientIP } = require('./middleware/ipFilter');
const { createRateLimiter } = require('./middleware/rateLimiter');
const { createWafRules } = require('./middleware/wafRules');
const logger = require('./middleware/logger');
const requestId = require('./middleware/requestId');
const apiSecurity = require('./middleware/apiSecurity');
const proxy = require('./proxy/proxyServer');

const app = express();
let server;

app.disable('x-powered-by');
app.set('trust proxy', config.trustProxyHops);
app.locals.config = config;

app.use(requestId);
app.use(resolveClientIP);
app.use(apiSecurity(config));
app.use('/api', express.json({ limit: '32kb', strict: true }));

app.get('/api/health', async (req, res, next) => {
  try {
    const redisReady = await isRedisReady();
    const mongoReady = mongoose.connection.readyState === 1;
    const healthy = redisReady && mongoReady;
    res.status(healthy ? 200 : 503).json({
      status: healthy ? 'ok' : 'degraded',
      services: {
        redis: redisReady ? 'connected' : 'disconnected',
        mongo: mongoReady ? 'connected' : 'disconnected',
      },
      requestId: req.requestId,
    });
  } catch (error) {
    next(error);
  }
});

app.use('/api/auth', buildAuthRouter({ config, redisClient }));
app.use('/api/dashboard', buildDashboardRouter({
  config,
  redisClient,
  services: {
    answerSecurityQuestion: createSecurityAssistant({
      apiKey: config.openRouterApiKey,
      model: config.openRouterModel,
    }),
  },
}));
app.use('/api', (req, res) => {
  res.status(404).json({ error: 'API route not found.', requestId: req.requestId });
});

app.use(express.json({ limit: '1mb', strict: true }));
app.use(express.urlencoded({ extended: false, limit: '1mb', parameterLimit: 100 }));

app.use(createIpFilter({ redisClient }));
app.use(createRateLimiter(config));
app.use(createWafRules());
app.use(logger);
app.use(proxy);

app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);

  const malformedJson =
    error instanceof SyntaxError &&
    error.status === 400 &&
    Object.prototype.hasOwnProperty.call(error, 'body');

  if (malformedJson) {
    return res.status(400).json({
      error: 'Request body must contain valid JSON.',
      requestId: req.requestId,
    });
  }

  if (error.type === 'entity.too.large') {
    return res.status(413).json({
      error: 'Request body exceeds the allowed size.',
      requestId: req.requestId,
    });
  }

  console.error(`Request ${req.requestId || 'unknown'} failed:`, error);
  return res.status(503).json({
    error: 'The request could not be completed because a required service is unavailable.',
    requestId: req.requestId,
  });
});

async function closeDependencies() {
  const operations = [];
  if (redisClient.isOpen) operations.push(redisClient.quit());
  if (mongoose.connection.readyState !== 0) operations.push(mongoose.disconnect());
  await Promise.all(operations);
}

async function startServer() {
  if (server) return server;

  try {
    await Promise.all([
      redisClient.isOpen ? Promise.resolve() : redisClient.connect(),
      mongoose.connect(config.mongoUri, {
        serverSelectionTimeoutMS: 5000,
        maxPoolSize: 20,
      }),
    ]);
    await Promise.all([SecurityEvent.init(), User.init()]);
  } catch (error) {
    await closeDependencies().catch((closeError) => {
      console.error('Failed to close backend dependencies after startup error:', closeError);
    });
    throw new Error(
      `Backend startup requires reachable Redis and MongoDB services: ${error.message}`,
      { cause: error },
    );
  }

  server = await new Promise((resolve, reject) => {
    const httpServer = app.listen(config.port);
    httpServer.once('listening', () => resolve(httpServer));
    httpServer.once('error', reject);
  });
  console.info(`AntiFlair API and proxy listening on port ${config.port}.`);
  return server;
}

async function stopServer() {
  if (server) {
    await new Promise((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
    server = undefined;
  }
  await closeDependencies();
}

if (require.main === module) {
  startServer().catch((error) => {
    console.error('Failed to start AntiFlair backend:', error);
    process.exitCode = 1;
  });

  for (const signal of ['SIGINT', 'SIGTERM']) {
    process.once(signal, () => {
      stopServer()
        .then(() => process.exit(0))
        .catch((error) => {
          console.error('Failed to shut down AntiFlair backend cleanly:', error);
          process.exit(1);
        });
    });
  }
}

module.exports = { app, startServer, stopServer };
