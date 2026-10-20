const { recordEvent } = require('../../database/services/eventService');

const rules = [
  {
    name: 'sql_injection',
    pattern: /\bunion\s+(?:all\s+)?select\b|\bselect\b.{0,120}\bfrom\b|\b(?:drop|delete)\s+table\b|(?:'|%27)\s*(?:or|and)\s+(?:'?\w+'?\s*=\s*'?\w+|1\s*=\s*1)/i,
  },
  {
    name: 'cross_site_scripting',
    pattern: /<\s*script\b|javascript\s*:|on(?:error|load|click)\s*=/i,
  },
  {
    name: 'path_traversal',
    pattern: /(?:^|[\\/])\.\.(?:[\\/]|%2f|%5c)/i,
  },
  {
    name: 'dangerous_sql_statement',
    pattern: /(?:--|\/\*|\*\/)\s*(?:drop|delete|insert|update)\b/i,
  },
];

function payloadToString(input) {
  if (input === undefined || input === null) return '';
  if (typeof input === 'string') return input.slice(0, 65536);

  try {
    return JSON.stringify(input).slice(0, 65536);
  } catch {
    return '';
  }
}

function inspectPayload(input) {
  const original = payloadToString(input);
  const candidates = [original];

  let decoded = original;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      const next = decodeURIComponent(decoded);
      if (next === decoded) break;
      decoded = next;
      candidates.push(decoded);
    } catch {
      break;
    }
  }

  for (const rule of rules) {
    if (candidates.some((candidate) => rule.pattern.test(candidate))) {
      return rule.name;
    }
  }

  return null;
}

function createWafRules() {
  return async function wafRules(req, res, next) {
    const matchedRule =
      inspectPayload(req.originalUrl) ||
      inspectPayload(req.query) ||
      inspectPayload(req.body);

    if (!matchedRule) return next();

    try {
      await recordEvent({
        category: 'waf',
        outcome: 'blocked',
        method: req.method,
        path: req.originalUrl,
        ip: req.clientIP,
        statusCode: 403,
        reason: matchedRule,
        requestId: req.requestId,
      });

      return res.status(403).json({
        error: 'Request blocked by the web application firewall.',
        rule: matchedRule,
        requestId: req.requestId,
      });
    } catch (error) {
      next(error);
    }
  };
}

module.exports = { createWafRules, inspectPayload };
