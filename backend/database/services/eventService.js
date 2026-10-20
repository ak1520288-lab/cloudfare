const SecurityEvent = require('../models/SecurityEvent');

function sanitizeEvent(event) {
  return {
    category: event.category,
    outcome: event.outcome,
    method: event.method ? String(event.method).slice(0, 12) : undefined,
    path: event.path ? String(event.path).split('?')[0].slice(0, 512) : undefined,
    ip: event.ip ? String(event.ip).slice(0, 64) : undefined,
    statusCode: Number.isInteger(event.statusCode) ? event.statusCode : undefined,
    reason: event.reason ? String(event.reason).replace(/[\r\n]/g, ' ').slice(0, 240) : undefined,
    actor: event.actor ? String(event.actor).slice(0, 64) : undefined,
    requestId: event.requestId ? String(event.requestId).slice(0, 64) : undefined,
    durationMs: Number.isFinite(event.durationMs)
      ? Math.max(0, Math.round(event.durationMs))
      : undefined,
  };
}

function recordEvent(event) {
  return SecurityEvent.create(sanitizeEvent(event));
}

module.exports = { recordEvent };
