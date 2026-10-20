const { isIP } = require('node:net');
const express = require('express');
const mongoose = require('mongoose');
const SecurityEvent = require('../../database/models/SecurityEvent');
const { inspectPayload } = require('../middleware/wafRules');
const { recordEvent } = require('../../database/services/eventService');
const {
  blockIP,
  isRedisReady,
  listBlockedIPs,
  unblockIP,
} = require('../../database/services/redisService');
const { requireAuth, requireCsrf, requireAdmin } = require('../middleware/apiAuth');

const VALID_CATEGORIES = ['proxy', 'rate_limit', 'waf', 'ip_block', 'auth', 'admin'];
const CHAT_RATE_LIMIT = 8;
const CHAT_RATE_WINDOW_SECONDS = 60;

function asyncRoute(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

function validPublicSiteUrl(value) {
  if (typeof value !== 'string' || value.length > 2048) return null;
  try {
    const url = new URL(value);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
      return null;
    }
    return url;
  } catch {
    return null;
  }
}

function buildDashboardRouter({
  config,
  redisClient,
  services = {},
}) {
  const router = express.Router();
  const authenticate = requireAuth(redisClient, config);
  const EventModel = services.SecurityEvent || SecurityEvent;
  const writeEvent = services.recordEvent || recordEvent;
  const checkRedisReady = services.isRedisReady || isRedisReady;
  const getBlockedIPs = services.listBlockedIPs || listBlockedIPs;
  const addBlockedIP = services.blockIP || blockIP;
  const removeBlockedIP = services.unblockIP || unblockIP;
  const validateIP = services.isIP || isIP;
  const answerSecurityQuestion = services.answerSecurityQuestion;
  const incrementChatCount = services.incrementChatCount || (async (ip) => {
    const count = await redisClient.eval(
      "local count = redis.call('INCR', KEYS[1]); if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]); end; return count",
      { keys: [`chat-rate:${ip}`], arguments: [String(CHAT_RATE_WINDOW_SECONDS)] },
    );
    return Number(count);
  });
  router.use(authenticate);

  router.get(
    '/summary',
    asyncRoute(async (req, res) => {
      const now = Date.now();
      const dayAgo = new Date(now - 24 * 60 * 60 * 1000);
      const minuteAgo = new Date(now - 60 * 1000);
      const [
        total24h,
        blocked24h,
        forwarded24h,
        requestsLastMinute,
        redisReady,
        blockedIPs,
      ] = await Promise.all([
        EventModel.countDocuments({ createdAt: { $gte: dayAgo } }),
        EventModel.countDocuments({
          createdAt: { $gte: dayAgo },
          outcome: 'blocked',
        }),
        EventModel.countDocuments({
          createdAt: { $gte: dayAgo },
          category: 'proxy',
          outcome: { $in: ['allowed', 'warning'] },
        }),
        EventModel.countDocuments({
          createdAt: { $gte: minuteAgo },
          category: 'proxy',
        }),
        checkRedisReady(),
        getBlockedIPs(),
      ]);

      res.json({
        generatedAt: new Date(now).toISOString(),
        metrics: {
          events24h: total24h,
          blocked24h,
          forwarded24h,
          requestsLastMinute,
          activeBlocks: blockedIPs.length,
        },
        services: {
          redis: redisReady ? 'connected' : 'disconnected',
          mongo: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
          origin: config.originServer,
        },
        modules: [
          { id: 'proxy', name: 'Reverse proxy', status: 'active' },
          { id: 'ip_block', name: 'IP blocklist', status: redisReady ? 'active' : 'unavailable' },
          { id: 'rate_limit', name: 'Rate limiting', status: redisReady ? 'active' : 'unavailable' },
          { id: 'waf', name: 'Basic WAF', status: 'active' },
          { id: 'audit_log', name: 'Persistent event log', status: mongoose.connection.readyState === 1 ? 'active' : 'unavailable' },
          { id: 'bot_score', name: 'Bot behavior scoring', status: 'roadmap' },
          { id: 'challenge', name: 'Challenge / CAPTCHA', status: 'roadmap' },
          { id: 'forecast', name: 'Predictive alerts', status: 'roadmap' },
        ],
      });
    }),
  );

  router.get(
    '/events',
    asyncRoute(async (req, res) => {
      const requestedLimit = Number(req.query.limit || 20);
      const requestedOffset = Number(req.query.offset || 0);
      if (
        !Number.isInteger(requestedLimit) ||
        requestedLimit < 1 ||
        requestedLimit > 100 ||
        !Number.isInteger(requestedOffset) ||
        requestedOffset < 0 ||
        requestedOffset > 10000
      ) {
        return res.status(400).json({ error: 'Use a limit from 1 to 100 and offset from 0 to 10000.' });
      }

      const filter = {};
      if (req.query.category !== undefined) {
        if (
          typeof req.query.category !== 'string' ||
          !VALID_CATEGORIES.includes(req.query.category)
        ) {
          return res.status(400).json({ error: 'Unknown event category.' });
        }
        filter.category = req.query.category;
      }
      if (req.query.outcome !== undefined) {
        if (
          typeof req.query.outcome !== 'string' ||
          !['allowed', 'blocked', 'warning'].includes(req.query.outcome)
        ) {
          return res.status(400).json({ error: 'Unknown event outcome.' });
        }
        filter.outcome = req.query.outcome;
      }
      if (req.query.ip !== undefined) {
        const ip = typeof req.query.ip === 'string'
          ? req.query.ip.trim().replace(/^::ffff:/i, '')
          : '';
        if (!validateIP(ip)) {
          return res.status(400).json({ error: 'Provide a valid IPv4 or IPv6 address filter.' });
        }
        filter.ip = ip;
      }
      if (req.query.from !== undefined || req.query.to !== undefined) {
        const from = typeof req.query.from === 'string' ? new Date(req.query.from) : null;
        const to = typeof req.query.to === 'string' ? new Date(req.query.to) : null;
        if (
          (req.query.from !== undefined && (!from || Number.isNaN(from.getTime()))) ||
          (req.query.to !== undefined && (!to || Number.isNaN(to.getTime()))) ||
          (from && to && from > to)
        ) {
          return res.status(400).json({ error: 'Provide valid dates with "from" no later than "to".' });
        }
        filter.createdAt = {};
        if (from) filter.createdAt.$gte = from;
        if (to) filter.createdAt.$lte = to;
      }

      const [events, total] = await Promise.all([
        EventModel.find(filter)
          .sort({ createdAt: -1, _id: -1 })
          .skip(requestedOffset)
          .limit(requestedLimit)
          .select('-_id category outcome method path ip statusCode reason actor requestId durationMs createdAt')
          .lean(),
        EventModel.countDocuments(filter),
      ]);

      res.json({ events, total, limit: requestedLimit, offset: requestedOffset });
    }),
  );

  router.get('/blocks', asyncRoute(async (req, res) => {
    res.json({ blocks: await getBlockedIPs() });
  }));

  router.post(
    '/chat',
    requireAdmin,
    requireCsrf,
    asyncRoute(async (req, res) => {
      const question = typeof req.body?.question === 'string' ? req.body.question.trim() : '';
      if (question.length < 2 || question.length > 1000) {
        return res.status(400).json({ error: 'Enter a security question from 2 to 1000 characters.' });
      }
      const history = req.body?.history === undefined ? [] : req.body.history;
      if (
        !Array.isArray(history) ||
        history.length > 8 ||
        history.some((message) =>
          !message ||
          !['user', 'assistant'].includes(message.role) ||
          typeof message.content !== 'string' ||
          message.content.trim().length < 1 ||
          message.content.length > 2000
        )
      ) {
        return res.status(400).json({ error: 'Chat history is invalid or too long. Start a new question.' });
      }
      const safeHistory = history.map(({ role, content }) => ({
        role,
        content: content.trim(),
      }));
      if (typeof answerSecurityQuestion !== 'function') {
        return res.status(503).json({ error: 'The security assistant is unavailable.' });
      }

      const clientIP = req.clientIP || req.ip || req.socket.remoteAddress;
      const count = await incrementChatCount(clientIP);
      if (count > CHAT_RATE_LIMIT) {
        res.setHeader('Retry-After', CHAT_RATE_WINDOW_SECONDS);
        return res.status(429).json({ error: 'Chat limit reached. Please wait a minute before asking again.' });
      }

      try {
        const answer = await answerSecurityQuestion(question, safeHistory);
        return res.json({ answer });
      } catch (error) {
        if (Number.isInteger(error.status) && error.status >= 400 && error.status <= 599) {
          return res.status(error.status).json({ error: error.message });
        }
        throw error;
      }
    }),
  );

  router.post(
    '/blocks',
    requireAdmin,
    requireCsrf,
    asyncRoute(async (req, res) => {
      const { ip, durationSeconds, reason } = req.body || {};
      const normalizedIP =
        typeof ip === 'string' ? ip.trim().replace(/^::ffff:/i, '') : '';
      const duration = durationSeconds === undefined ? config.proxyBlockSeconds : Number(durationSeconds);

      if (!validateIP(normalizedIP)) {
        return res.status(400).json({ error: 'Provide a valid IPv4 or IPv6 address.' });
      }
      if (!Number.isInteger(duration) || duration < 60 || duration > 86400) {
        return res.status(400).json({ error: 'Block duration must be from 60 to 86400 seconds.' });
      }

      const safeReason =
        typeof reason === 'string' && reason.trim()
          ? reason.replace(/[\r\n]/g, ' ').trim().slice(0, 120)
          : 'manual_admin_block';
      await addBlockedIP(normalizedIP, duration, safeReason);
      try {
        await writeEvent({
          category: 'admin',
          outcome: 'blocked',
          method: req.method,
          path: req.path,
          ip: normalizedIP,
          statusCode: 201,
          reason: safeReason,
          actor: req.adminSession.username,
          requestId: req.requestId,
        });
      } catch (error) {
        console.error(`IP block was applied but its audit record failed (request ${req.requestId}):`, error);
        return res.status(503).json({
          error: 'The IP block was applied, but its audit record could not be saved. Check active blocks before retrying.',
          requestId: req.requestId,
        });
      }

      res.status(201).json({ block: { ip: normalizedIP, reason: safeReason, ttlSeconds: duration } });
    }),
  );

  router.delete(
    '/blocks/:ip',
    requireAdmin,
    requireCsrf,
    asyncRoute(async (req, res) => {
      const ip = req.params.ip.replace(/^::ffff:/i, '');
      if (!validateIP(ip)) {
        return res.status(400).json({ error: 'Provide a valid IPv4 or IPv6 address.' });
      }

      const removed = await removeBlockedIP(ip);
      if (!removed) {
        return res.status(404).json({ error: 'No active block exists for this IP address.' });
      }

      try {
        await writeEvent({
          category: 'admin',
          outcome: 'allowed',
          method: req.method,
          path: req.path,
          ip,
          statusCode: 200,
          reason: 'manual_admin_unblock',
          actor: req.adminSession.username,
          requestId: req.requestId,
        });
      } catch (error) {
        console.error(`IP block was removed but its audit record failed (request ${req.requestId}):`, error);
        return res.status(503).json({
          error: 'The IP block was removed, but its audit record could not be saved. Verify the active block list.',
          requestId: req.requestId,
        });
      }
      res.json({ unblocked: ip });
    }),
  );

  router.post(
    '/inspect',
    requireCsrf,
    (req, res) => {
      const url = validPublicSiteUrl(req.body?.url);
      if (!url) {
        return res.status(400).json({
          error: 'Provide a valid HTTP or HTTPS URL without embedded credentials.',
        });
      }

      const matchedRule = inspectPayload(`${url.pathname}${url.search}`);
      res.json({
        host: url.hostname,
        inspectedAt: new Date().toISOString(),
        contactedTarget: false,
        result: matchedRule ? 'would_block' : 'no_basic_rule_match',
        rule: matchedRule,
        message: matchedRule
          ? `The configured basic WAF rules match: ${matchedRule}.`
          : 'No configured basic WAF pattern matched the submitted URL path. This is not a complete security scan.',
      });
    },
  );

  router.use((req, res) => res.status(404).json({ error: 'Dashboard API route not found.' }));
  return router;
}

module.exports = { buildDashboardRouter, validPublicSiteUrl };
